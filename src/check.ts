import {Server as StellarServer} from 'stellar-sdk'
import {Uid, Sha256Hash, Sha512Hash, PathAndSigsJSON, ChainLinkJSON, KeybaseSig, Sig2Payload, TreeRoots, PathNodeJSON} from './types'
import {horizonServerURI, keybaseStellarAddress, keybaseRootKid, keybaseAPIServerURI} from './constants'
import {URLSearchParams} from 'url'
import axios from 'axios'
import {promisify} from 'util'
import {createHash} from 'crypto'
import {kb} from 'kbpgp'
import {decode} from '@msgpack/msgpack'
import {Reporter, NullReporter, InteractiveReporter} from './reporter'
import chalk from 'chalk'

const sha256 = (b: Buffer): Sha256Hash => {
  return createHash('sha256')
    .update(b)
    .digest('hex') as Sha256Hash
}

const sha512 = (b: Buffer): Sha512Hash => {
  return createHash('sha512')
    .update(b)
    .digest('hex') as Sha512Hash
}

// The overall layout of data is as follows:
//
// PathAndSigsJSON (as returned by merkle/ptah for UID)
//    - path: from merkle root to leaf for uid
//    - sigs: signatures
//        - merkle roots (type: TreeRoots)
//            - main tree Root (for users and teams)
//            - legacy username->UID mapping tree root
//

const uint8ArrayToHex = (u: Uint8Array): string => Buffer.from(u).toString('hex')

export class Checker {
  reporter: Reporter

  constructor() {
    this.reporter = new NullReporter()
  }

  async fetchLatestGroveHashFromStellar(): Promise<Sha256Hash> {
    const reporter = this.reporter.step(`fetch latest root from ${chalk.bold('stellar')}`)
    const horizonServer = new StellarServer(horizonServerURI)
    reporter.start(`contact ${horizonServerURI}`)
    const txList = await horizonServer
      .transactions()
      .forAccount(keybaseStellarAddress)
      .order('desc')
      .call()
    if (txList.records.length == 0) {
      throw new Error('did not find any transactions')
    }
    const rec = txList.records[0]
    const ledger = await rec.ledger()
    if (rec.memo_type != 'hash') {
      throw new Error('needed a hash type of memo')
    }
    const buf = Buffer.from(rec.memo, 'base64')
    if (buf.length != 32) {
      throw new Error('need a 32-byte SHA2 hash')
    }
    reporter.success(`returned #${ledger.sequence}, closed at ${ledger.closed_at}`)
    return buf.toString('hex') as Sha256Hash
  }

  async fetchPathAndSigs(groveHash: Sha256Hash, uid: Uid): Promise<PathAndSigsJSON> {
    const params = new URLSearchParams({uid: uid})
    params.append('start_hash256', groveHash)
    const reporter = this.reporter.step(`fetch ${chalk.bold('keybase')} path from root for ${chalk.italic(uid)}`)
    const url = keybaseAPIServerURI + 'merkle/path.json?' + params.toString()
    reporter.start(`contact ${url}`)
    const response = await axios.get(url)
    const ret = response.data as PathAndSigsJSON
    if (ret.status.code != 0) {
      throw new Error(`error fetching user: ${ret.status.desc}`)
    }
    reporter.success(`got back seqno #${ret.root.seqno}`)
    return ret
  }

  extractUid(username: string, pathAndSigs: PathAndSigsJSON, legacyUidRootHash: Sha256Hash): Uid {
    const hsh = sha256(Buffer.from(username.toLowerCase(), 'ascii'))
    const potentialUid = (hsh.slice(0, 30) + '19') as Uid
    const reporter = this.reporter.step(`extract UID for ${chalk.italic(username)}`)
    reporter.start()
    if (potentialUid == pathAndSigs.uid) {
      reporter.success(`map to ${chalk.italic(potentialUid)} via hash`)
      return potentialUid
    }
    this.checkUidAgainstLegacyTree(hsh, pathAndSigs.uid, pathAndSigs.uid_proof_path, legacyUidRootHash)
    const ret = pathAndSigs.uid
    reporter.success(`map to ${chalk.italic(ret)} via legacy tree`)
    return ret
  }

  // Some of the earliest Keybase accounts had uids that were random and didn't reflect the
  // corresponding usernames in anyway. This allowed the server to lie about the username<>UID
  // mapping. We then transitioned to a system where the UID was derived from the username to
  // remove this attack vector, but about ~40k of the legacy usernames are still supported.
  // The server commits to them via this static merkle tree.
  checkUidAgainstLegacyTree(usernameHash: Sha256Hash, uid: Uid, uidProofPath: PathNodeJSON[], expectedHash: Sha256Hash) {
    let i = 1
    for (const step of uidProofPath) {
      const prefix = usernameHash.slice(0, i)
      const nodeValue = step.node.val
      const gotHash = sha256(Buffer.from(nodeValue, 'ascii'))
      const childrenTable = JSON.parse(nodeValue).tab
      if (gotHash != expectedHash) {
        throw new Error(`bad hash at prefix ${prefix} of legacy UID tree ${gotHash} ${expectedHash}`)
      }
      if (step.node.type == 2) {
        const foundUid = childrenTable[usernameHash]
        if (foundUid !== uid) {
          throw new Error('bad UID found in legacy UID tree')
        }
        return
      }
      expectedHash = childrenTable[prefix]
      i++
    }
    throw new Error('walked off the end of the tree')
  }

  async fetchPathAndSigsForUsername(groveHash: Sha256Hash, username: string): Promise<PathAndSigsJSON> {
    const params = new URLSearchParams({username: username})
    params.append('start_hash256', groveHash)
    const reporter = this.reporter.step(`fetch ${chalk.bold('keybase')} path from root for ${chalk.italic(username)}`)
    const url = keybaseAPIServerURI + 'merkle/path.json?' + params.toString()
    reporter.start(`contact ${chalk.grey(url)}`)
    const response = await axios.get(url)
    const ret = response.data as PathAndSigsJSON
    if (ret.status.code != 0) {
      throw new Error(`error fetching user: ${ret.status.desc}`)
    }
    reporter.success(`got back seqno #${ret.root.seqno}`)
    return ret
  }

  async checkSigAgainstStellar(pathAndSigs: PathAndSigsJSON, expectedHash: Sha256Hash): Promise<TreeRoots> {
    // First check that the hash of the signature was reflected in the
    // stellar blockchain, as expected.
    const reporter = this.reporter.step(`check hash equality for ${chalk.italic(expectedHash)}`)
    reporter.start()
    const sig = pathAndSigs.root.sigs[keybaseRootKid].sig
    const buf = Buffer.from(sig, 'base64')
    const gotHash = sha256(buf)
    if (expectedHash != gotHash) {
      throw new Error('hash mismatch for root sig and stellar memo')
    }

    // Verify the signature is valid, and signed with the expected key
    const f = promisify(kb.verify)
    const sigPayload = await f({binary: buf, kid: keybaseRootKid})

    // The next 5 lines aren't necessary, since they are already performed inside
    // of kb.verify, but we repeat them here to be explicit that the `sig` object
    // also contains the text of what the signature was over.
    const object = decode(buf) as KeybaseSig
    const treeRootsEncoded = Buffer.from(object.body.payload)
    if (sigPayload.compare(treeRootsEncoded) != 0) {
      throw new Error('buffer comparison failed and should have been the same')
    }

    // Parse and return the root sig payload
    reporter.success('match')
    return JSON.parse(treeRootsEncoded.toString('ascii')) as TreeRoots
  }

  walkPathToLeaf(pathAndSigs: PathAndSigsJSON, expectedHash: Sha512Hash, uid: Uid): Sha256Hash {
    let i = 1
    const reporter = this.reporter.step(`walk path to leaf for ${chalk.italic(uid)}`)
    for (const step of pathAndSigs.path) {
      const prefix = uid.slice(0, i)
      const nodeValue = step.node.val
      const childrenTable = JSON.parse(nodeValue).tab
      const gotHash = sha512(Buffer.from(nodeValue, 'ascii'))

      if (gotHash != expectedHash) {
        throw new Error(`hash mismatch at prefix ${prefix}`)
      }

      reporter.update(`ok at ${prefix} / ${gotHash}`)

      // node.type == 2 means that it's a leaf rather than an interior leaf.
      // stop walking and exit here
      if (step.node.type == 2) {
        const leaf = childrenTable[uid]
        // The hash of the tail of the user's sigchain is found at .[1][1]
        // relative to what's stored in the merkle tree leaf.
        const tailHash = leaf[1][1] as Sha256Hash
        reporter.success(`tail hash is ${chalk.italic(tailHash)}`)
        return tailHash
      }

      expectedHash = childrenTable[prefix]
      i++
    }
    throw new Error('walked off the end of the tree')
  }

  checkLink(sig: any, expectedHash: Sha256Hash, i: number): {payload: ChainLinkJSON; prev: Sha256Hash} {
    // Sig version 1 and 2 both have a "payload" as a JSON object,
    // which signifies what the signature was attesting to.
    const innerString = sig.payload_json
    const inner = JSON.parse(innerString) as ChainLinkJSON
    const version = sig.sig_version
    const innerHash = sha256(Buffer.from(innerString, 'ascii'))
    let gotHash = innerHash

    // Sig version 2 uses an additional level of indirection for the sake
    // of bandiwdth savings. An "outer" link points to the "inner"
    // link above by a hash.
    if (version == 2) {
      const object = decode(Buffer.from(sig.sig, 'base64')) as KeybaseSig
      const outerBuf = object.body.payload
      gotHash = sha256(outerBuf)
      const outer = decode(outerBuf) as Sig2Payload
      const prev = uint8ArrayToHex(outer[2])
      if (prev != inner.prev) {
        throw new Error(`bad prev/prev mismatch at position ${i}`)
      }
      if (innerHash != uint8ArrayToHex(outer[3])) {
        throw new Error(`bad inner mismatch at position ${i}`)
      }
    }

    if (gotHash != expectedHash) {
      throw new Error(`bad sigchain link at ${i}`)
    }

    return {payload: inner, prev: inner.prev}
  }

  // fetch the sig chain for the give user; assert that the chain ends in the
  // given hash. Return the JSON of the links, from oldest to newest.
  async fetchSigChain(h: Sha256Hash, uid: Uid): Promise<ChainLinkJSON[]> {
    const reporter = this.reporter.step(`fetch sigchain from ${chalk.bold('keybase')} for ${chalk.italic(uid)}`)
    const url = keybaseAPIServerURI + 'sig/get.json?uid=' + uid
    reporter.start(`contact ${chalk.grey(url)}`)
    const response = await axios.get(url)
    const sigs = response.data.sigs
    const numSigs = sigs.length
    const ret: ChainLinkJSON[] = []
    let expectedHash = h
    for (let i = numSigs - 1; i >= 0; i--) {
      const {payload, prev} = this.checkLink(sigs[i], expectedHash, i)
      expectedHash = prev
      ret.push(payload)
    }
    reporter.success(`got back ${ret.length} links`)
    return ret.reverse()
  }

  // checkUid traverses the stellar root down to the given Uid, and returns the
  // full sigchain of the user. This function is kept simple for the basis
  // of site documentation.
  async checkUid(uid: Uid): Promise<ChainLinkJSON[]> {
    const groveHash = await this.fetchLatestGroveHashFromStellar()
    const pathAndSigs = await this.fetchPathAndSigs(groveHash, uid)
    const treeRoots = await this.checkSigAgainstStellar(pathAndSigs, groveHash)
    const rootHash = treeRoots.body.root
    const chainTail = this.walkPathToLeaf(pathAndSigs, rootHash, uid)
    const chain = await this.fetchSigChain(chainTail, uid)
    return chain
  }

  // checkUsername traverses the stellar root down to the given username, and returns the
  // full sigchain of the user. This function is kept simple for the basis
  // of site documentation.
  async checkUsername(username: string): Promise<ChainLinkJSON[]> {
    const groveHash = await this.fetchLatestGroveHashFromStellar()
    const pathAndSigs = await this.fetchPathAndSigsForUsername(groveHash, username)
    const treeRoots = await this.checkSigAgainstStellar(pathAndSigs, groveHash)
    const uid = this.extractUid(username, pathAndSigs, treeRoots.body.legacy_uid_root)
    const chainTail = this.walkPathToLeaf(pathAndSigs, treeRoots.body.root, uid)
    const chain = await this.fetchSigChain(chainTail, uid)
    return chain
  }

  // top-level function to the library. Give it a username or UID
  // and it will contact stellar, then keybase, then walk down the tree
  // to the leaf of the user, then fetch back their sigchain. It returns
  // the sigchain on success and null on error. It won't throw errors, it catches
  // them.
  async check(usernameOrUid: string): Promise<ChainLinkJSON[] | null> {
    try {
      if (usernameOrUid.match(/^[0-9a-f]{30}(00|19)$/)) {
        const ret = await this.checkUid(usernameOrUid as Uid)
        return ret
      }
      const ret = await this.checkUsername(usernameOrUid)
      return ret
    } catch (e) {
      this.reporter.error(e)
      return null
    }
  }

  interactiveReporting() {
    this.reporter = new InteractiveReporter()
  }
}
