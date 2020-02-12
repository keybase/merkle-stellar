import {Server as StellarServer, NetworkError} from 'stellar-sdk'
import {
  Uid,
  Sha256Hash,
  Sha512Hash,
  PathAndSigsJSON,
  ChainLinkBundle,
  KeybaseSig,
  Sig2Payload,
  TreeRoots,
  PathNodeJSON,
  ResetChain,
  ChainTails,
  UserSigChain,
  ResetChainLinkJSON,
  SigChainTail,
  RawLinkJSON,
  ChainMaxes,
  ChainLinkJSON,
} from './types'
import {horizonServerURI, keybaseStellarAddress, keybaseRootKid, keybaseAPIServerURI} from './constants'
import {URLSearchParams} from 'url'
import axios from 'axios'
import {promisify} from 'util'
import {createHash} from 'crypto'
import {kb} from 'kbpgp'
import {decode} from '@msgpack/msgpack'
import {Reporter, Step, newReporter} from './reporter'
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

const generateLogSequence = (n: number): number[] => {
  const ret: number[] = []
  let step = 1
  while (n > 0) {
    if ((n & 0x1) == 0x1) {
      ret.push(step)
    }
    n = n >> 1
    step = step << 1
  }
  return ret.reverse()
}

export class TreeWalker {
  reporter: Reporter

  constructor(r?: Reporter) {
    this.reporter = newReporter(r)
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

  async fetchPathAndSigsHistorical(uid: Uid, groveHash: Sha256Hash, last: number): Promise<PathAndSigsJSON> {
    const reporter = this.reporter.step(`fetch historical ${chalk.bold('keybase')} path from root for ${chalk.italic(uid)}`)
    const params = new URLSearchParams({uid: uid})
    params.append('start_hash256', groveHash)
    params.append('last', '' + last)
    return this.fetchPathAndSigsWithParams(params, reporter)
  }

  async fetchPathAndSigsForUid(uid: Uid): Promise<PathAndSigsJSON> {
    const params = new URLSearchParams({uid: uid})
    const reporter = this.reporter.step(`fetch ${chalk.bold('keybase')} path from root for ${chalk.italic(uid)}`)
    return this.fetchPathAndSigsWithParams(params, reporter)
  }

  async fetchPathAndSigsWithParams(params: URLSearchParams, step: Step): Promise<PathAndSigsJSON> {
    params.append('load_reset_chain', '1')
    const url = keybaseAPIServerURI + 'merkle/path.json?' + params.toString()
    step.start(`contact ${url}`)
    const response = await axios.get(url)
    const ret = response.data as PathAndSigsJSON
    if (ret.status.code != 0) {
      throw new Error(`error fetching user: ${ret.status.desc}`)
    }
    step.success(`got back seqno #${ret.root.seqno}`)
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

  async fetchPathAndSigsForUsername(username: string): Promise<PathAndSigsJSON> {
    const params = new URLSearchParams({username: username})
    const reporter = this.reporter.step(`fetch ${chalk.bold('keybase')} path from root for ${chalk.italic(username)}`)
    return this.fetchPathAndSigsWithParams(params, reporter)
  }

  async checkRootSigs(pathAndSigs: PathAndSigsJSON, expectedHash: Sha256Hash | null): Promise<[TreeRoots, Sha256Hash]> {
    // First check that the hash of the signature was reflected in the
    // stellar blockchain, as expected.
    const reporter = this.reporter.step(`check hash equality for ${chalk.italic(expectedHash)}`)
    reporter.start()
    const sig = pathAndSigs.root.sigs[keybaseRootKid].sig
    const sigDecoded = Buffer.from(sig, 'base64')
    const gotHash = sha256(sigDecoded)

    // We don't always need to pass in a sig from stellar; if the user's sigchain
    // is newer than the last stellar timestamp, we need to fetch without it;
    // the rest of the checks still work
    if (expectedHash && expectedHash != gotHash) {
      throw new Error('hash mismatch for grove sig and stellar memo')
    }

    // Verify the signature is valid, and signed with the expected key
    const f = promisify(kb.verify)
    const sigPayload = await f({binary: sigDecoded, kid: keybaseRootKid})

    // The next 5 lines aren't necessary, since they are already performed inside
    // of kb.verify, but we repeat them here to be explicit that the `sig` object
    // also contains the text of what the signature was over.
    const object = decode(sigDecoded) as KeybaseSig
    const treeRootsEncoded = Buffer.from(object.body.payload)
    if (sigPayload.compare(treeRootsEncoded) != 0) {
      throw new Error('buffer comparison failed and should have been the same')
    }
    const rootsHash = sha256(treeRootsEncoded)

    // Parse and return the root sig payload
    reporter.success(expectedHash ? 'match' : 'skipped')
    return [JSON.parse(treeRootsEncoded.toString('ascii')) as TreeRoots, rootsHash]
  }

  walkPathToLeaf(pathAndSigs: PathAndSigsJSON, expectedHash: Sha512Hash, uid: Uid): ChainTails {
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
        const leaf = childrenTable[uid] as ChainTails
        // The hash of the tail of the user's sigchain is found at .[1][1]
        // relative to what's stored in the merkle tree leaf.
        reporter.success(`tail hash is ${chalk.italic(leaf[1][1])}`)
        return leaf
      }

      expectedHash = childrenTable[prefix]
      i++
    }
    throw new Error('walked off the end of the tree')
  }

  checkLink(rawLink: RawLinkJSON, expectedHash: Sha256Hash | null, i: number): [ChainLinkBundle, Sha256Hash] {
    // Sig version 1 and 2 both have a "payload" as a JSON object,
    // which signifies what the signature was attesting to.
    const innerString = rawLink.payload_json
    const inner = JSON.parse(innerString) as ChainLinkJSON
    const version = rawLink.sig_version
    const innerHash = sha256(Buffer.from(innerString, 'ascii'))
    let gotHash = innerHash
    let outer: Sig2Payload = null

    // Sig version 2 uses an additional level of indirection for the sake
    // of bandiwdth savings. An "outer" link points to the "inner"
    // link above by a hash.
    if (version == 2) {
      const object = decode(Buffer.from(rawLink.sig, 'base64')) as KeybaseSig
      const outerBuf = object.body.payload
      gotHash = sha256(outerBuf)
      outer = decode(outerBuf) as Sig2Payload
      const prev = uint8ArrayToHex(outer[2])
      if (prev != inner.prev) {
        throw new Error(`bad prev/prev mismatch at position ${i}`)
      }
      if (innerHash != uint8ArrayToHex(outer[3])) {
        throw new Error(`bad inner mismatch at position ${i}`)
      }
      if (outer[1] != i) {
        throw new Error(`expected seqno ${i} on outer link; got ${outer[1]}`)
      }
    }

    if (expectedHash && gotHash != expectedHash) {
      throw new Error(`bad sigchain link at ${i} (${gotHash} != ${expectedHash})`)
    }
    if (inner.seqno != i) {
      throw new Error(`bad seqno ${inner.seqno} at position ${i}`)
    }

    const bundle: ChainLinkBundle = {inner: inner, outer: outer, sig: rawLink.sig, kid: rawLink.kid, payloadHash: gotHash}
    return [bundle, inner.prev]
  }

  checkResetChain(pathAndSigs: PathAndSigsJSON, chainTails: ChainTails, uid: Uid): ResetChain | null {
    const resetChainTail = chainTails[4]
    if (!resetChainTail || resetChainTail[0] == 0) {
      return null
    }
    const resetChain = pathAndSigs.reset_chain
    if (!resetChain) {
      throw new Error(`expected a reset chain but didn't find one`)
    }
    if (resetChain.length != resetChainTail[0]) {
      throw new Error(`reset chain tail is wrong length`)
    }

    let hashExpected = resetChainTail[1]
    const resetChainLinks = resetChain.reverse()
    let i = resetChainLinks.length
    let first = true
    const ret = [] as ResetChainLinkJSON[]
    for (const link of resetChainLinks) {
      const hash = sha512(Buffer.from(link, 'ascii'))
      if (hashExpected != hash) {
        throw new Error(`hash mismatch in reset chain`)
      }
      const parsedLink = JSON.parse(link) as ResetChainLinkJSON
      if (parsedLink.reset_seqno != i) {
        throw new Error(`bad reset chain seqno`)
      }
      if (!first && parsedLink.type == 'delete') {
        throw new Error(`can't have a delete in the middle of the reset chain`)
      }
      ret.push(parsedLink)
      hashExpected = parsedLink.prev.reset
      i--
      first = false
    }
    if (hashExpected) {
      throw new Error(`reset chain didn't start with a null prev hash`)
    }
    if (i != 0) {
      throw new Error(`reset chain doesn't start at 1`)
    }

    return ret.reverse()
  }

  async fetchRawChain(uid: Uid, low: number, reporter: Step): Promise<RawLinkJSON[]> {
    const url = keybaseAPIServerURI + 'sig/get.json?uid=' + uid
    reporter.update(`contact ${chalk.grey(url)}`)
    const response = await axios.get(url)
    const sigs = response.data.sigs as RawLinkJSON[]
    return sigs
  }

  // fetch the sig chain for the give user; assert that the chain ends in the
  // given hash. Return the JSON of the links, from oldest to newest.
  async fetchAndCheckChainLinks(assertions: Map<number, Sha256Hash>, uid: Uid): Promise<ChainLinkBundle[]> {
    const reporter = this.reporter.step(`fetch sigchain from ${chalk.bold('keybase')} for ${chalk.italic(uid)}`)
    reporter.start('fetch raw chain')
    const sigs = await this.fetchRawChain(uid, 0, reporter)
    const numSigs = sigs.length
    const ret: ChainLinkBundle[] = []

    // We usually have an assertion of link seqno -> hash for the last link, but
    // no always, there could have been a race
    let expectedHash = assertions.get(numSigs)

    for (let seqno = numSigs; seqno >= 1; seqno--) {
      const index = seqno - 1

      const assertedHash = assertions.get(seqno)
      if (assertedHash && expectedHash != assertedHash) {
        throw new Error(`got wrong expected hash (via tree) at ${seqno}`)
      }

      const [bundle, prev] = this.checkLink(sigs[index], expectedHash, seqno)
      expectedHash = prev
      ret.push(bundle)
    }
    reporter.success(`got back ${ret.length} links`)
    return ret.reverse()
  }

  checkSkips(latest: PathAndSigsJSON, latestTreeRoots: TreeRoots, historical: PathAndSigsJSON, historicalTreeRootsHash: Sha256Hash) {
    const reporter = this.reporter.step(`check skips from ${latest.root.seqno}<-${historical.root.seqno}`)
    reporter.start('')
    let currSeqno = latest.root.seqno
    const lastSeqno = historical.root.seqno
    const diff = currSeqno - lastSeqno
    if (diff == 0) {
      reporter.success('equal')
      return
    }
    const seq = generateLogSequence(diff)
    let curr = latestTreeRoots
    let i = 0
    let lastHash: Sha256Hash = null

    for (const jump of seq) {
      const nextSeqno = currSeqno - jump
      const nextHash = curr.body.skips['' + nextSeqno]
      if (!nextSeqno) {
        throw new Error(`server did not return a skip for seqno ${nextSeqno}`)
      }
      if (nextSeqno == lastSeqno) {
        lastHash = nextHash
        break
      }
      const nextEncoded = historical.skips[i]
      const computedHash = sha256(Buffer.from(nextEncoded, 'ascii'))
      if (computedHash != nextHash) {
        throw new Error(`root block hash mismatch at ${nextSeqno} ${computedHash} != ${nextHash}`)
      }
      reporter.update(`skipped to ${nextSeqno}`)
      const next = JSON.parse(nextEncoded) as TreeRoots
      curr = next
      currSeqno = nextSeqno
      i++
    }
    if (!lastHash) {
      throw new Error(`didn't end at final sequence ${lastSeqno}`)
    }
    if (lastHash != historicalTreeRootsHash) {
      throw new Error(`hash mismatch at final step ${lastSeqno}`)
    }
    reporter.success(`done`)
    return
  }

  checkChainGrowth(latest: SigChainTail, historical: SigChainTail): Map<number, Sha256Hash> {
    if (latest[0] < historical[0]) {
      throw new Error(`chain grew backwards between two merkle fetches`)
    }
    const ret = new Map<number, Sha256Hash>()
    ret.set(latest[0], latest[1])
    ret.set(historical[0], historical[1])
    return ret
  }

  // walkUid traverses the stellar root down to the given Uid, and returns the
  // full sigchain of the user. This function is kept simple for the basis
  // of site documentation.
  async walkUid(uid: Uid): Promise<UserSigChain> {
    const latestPathAndSigs = await this.fetchPathAndSigsForUid(uid)
    const [latestTreeRoots, _] = await this.checkRootSigs(latestPathAndSigs, null)
    return this.walkCommon(latestPathAndSigs, latestTreeRoots, uid)
  }

  makeChainMaxes(links: ChainLinkBundle[], latestChainTails: ChainTails, stellarChainTails: ChainTails): ChainMaxes {
    return new ChainMaxes({
      sig: links ? links.length : 0,
      merkle: latestChainTails[1][0],
      stellar: stellarChainTails[1][0],
    })
  }

  async walkCommon(latestPathAndSigs: PathAndSigsJSON, latestTreeRoots: TreeRoots, uid: Uid): Promise<UserSigChain> {
    const groveHash = await this.fetchLatestGroveHashFromStellar()
    const stellarPathAndSigs = await this.fetchPathAndSigsHistorical(uid, groveHash, latestTreeRoots.body.seqno)

    const latestRootHash = latestTreeRoots.body.root
    const latestChainTails = this.walkPathToLeaf(latestPathAndSigs, latestRootHash, uid)

    const [stellarTreeRoots, stellarRootsHash] = await this.checkRootSigs(stellarPathAndSigs, groveHash)
    this.checkSkips(latestPathAndSigs, latestTreeRoots, stellarPathAndSigs, stellarRootsHash)
    const stellarRootHash = stellarTreeRoots.body.root
    const stellarChainTails = this.walkPathToLeaf(stellarPathAndSigs, stellarRootHash, uid)

    const chainAssertions = this.checkChainGrowth(latestChainTails[1], stellarChainTails[1])

    const links = await this.fetchAndCheckChainLinks(chainAssertions, uid)
    const resets = this.checkResetChain(latestPathAndSigs, latestChainTails, uid)
    const chainMaxes = this.makeChainMaxes(links, latestChainTails, stellarChainTails)
    return {links: links, resets: resets, maxes: chainMaxes, eldest: latestChainTails[3], uid: uid} as UserSigChain
  }

  // walkUsername traverses the stellar root down to the given username, and returns the
  // full sigchain of the user. This function is kept simple for the basis
  // of site documentation.
  async walkUsername(username: string): Promise<UserSigChain> {
    const latestPathAndSigs = await this.fetchPathAndSigsForUsername(username)
    const [latestTreeRoots, _] = await this.checkRootSigs(latestPathAndSigs, null)
    const uid = this.extractUid(username, latestPathAndSigs, latestTreeRoots.body.legacy_uid_root)
    return this.walkCommon(latestPathAndSigs, latestTreeRoots, uid)
  }

  // top-level function to the library. Give it a username or UID
  // and it will contact stellar, then keybase, then walk down the tree
  // to the leaf of the user, then fetch back their sigchain. It returns
  // the sigchain on success and null on error. It won't throw errors, it catches
  // them.
  async walk(usernameOrUid: string): Promise<UserSigChain> {
    try {
      const ret = await this.walkUidOrUsername(usernameOrUid)
      return ret
    } catch (e) {
      this.reporter.error(e)
      return null
    }
  }

  async walkUidOrUsername(usernameOrUid: string): Promise<UserSigChain> {
    if (usernameOrUid.match(/^[0-9a-f]{30}(00|19)$/)) {
      const ret = await this.walkUid(usernameOrUid as Uid)
      return ret
    }
    const ret = await this.walkUsername(usernameOrUid)
    return ret
  }
}
