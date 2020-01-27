import {Server as StellarServer} from 'stellar-sdk'
import {Uid, Sha256Hash, Sha512Hash, PathFromRootJSON, ChainLinkJSON, KeybaseSig, Sig2Payload} from './types'
import {horizonServerURI, keybaseStellarAddress, keybaseRootKid, keybaseAPIServerURI} from './constants'
import {URLSearchParams} from 'url'
import axios from 'axios'
import {promisify} from 'util'
import {createHash} from 'crypto'
import {kb} from 'kbpgp'
import {decode} from '@msgpack/msgpack'

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

const fetchLatestRootHashFromStellar = async (): Promise<Sha256Hash> => {
  const horizonServer = new StellarServer(horizonServerURI)
  const txList = await horizonServer
    .transactions()
    .forAccount(keybaseStellarAddress)
    .order('desc')
    .call()
  if (txList.records.length == 0) {
    throw new Error('did not find any transactions')
  }
  const rec = txList.records[0]
  if (rec.memo_type != 'hash') {
    throw new Error('needed a hash type of memo')
  }
  const buf = Buffer.from(rec.memo, 'base64')
  if (buf.length != 32) {
    throw new Error('need a 32-byte SHA2 hash')
  }
  return buf.toString('hex') as Sha256Hash
}

const fetchPathFromRoot = async (rootHash: Sha256Hash, uid: Uid): Promise<PathFromRootJSON> => {
  const params = new URLSearchParams({uid: uid})
  params.append('start_hash256', rootHash)
  const url = keybaseAPIServerURI + 'merkle/path.json?' + params.toString()
  const response = await axios.get(url)
  return response.data as PathFromRootJSON
}

const checkSigAgainstStellar = async (pathFromRootJSON: PathFromRootJSON, expectedHash: Sha256Hash): Promise<Buffer> => {
  // First check that the hash of the signature was reflected in the
  // stellar blockchain, as expected.
  const sig = pathFromRootJSON.root.sigs[keybaseRootKid].sig
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
  const sigPayload2 = object.body.payload
  if (sigPayload.compare(sigPayload2) != 0) {
    throw new Error('buffer comparison failed and should have been the same')
  }

  return sigPayload
}

const extractRootFromSigPayload = (sigPayload: Buffer): Sha512Hash => {
  const payload = JSON.parse(sigPayload.toString('ascii'))
  return payload.body.root as Sha512Hash
}

const walkPathToLeaf = (pathFromRoot: PathFromRootJSON, expectedHash: Sha512Hash, uid: Uid): Sha256Hash => {
  let i = 1
  for (const step of pathFromRoot.path) {
    const prefix = uid.slice(0, i)
    const nodeValue = step.node.val
    const childrenTable = JSON.parse(nodeValue).tab
    const gotHash = sha512(Buffer.from(nodeValue, 'ascii'))

    if (gotHash != expectedHash) {
      throw new Error(`hash mismatch at prefix ${prefix}`)
    }

    // node.type == 2 means that it's a leaf rather than an interior leaf.
    // stop walking and exit here
    if (step.node.type == 2) {
      const leaf = childrenTable[uid]
      // The hash of the tail of the user's sigchain is found at .[1][1]
      // relative to what's stored in the merkle tree leaf.
      const tailHash = leaf[1][1] as Sha256Hash
      return tailHash
    }

    expectedHash = childrenTable[prefix]
    i++
  }
  throw new Error('walked off the end of the tree')
}

const uint8ArrayToHex = (u: Uint8Array): string => Buffer.from(u).toString('hex')

const checkLink = (sig: any, expectedHash: Sha256Hash, i: number): {payload: ChainLinkJSON; prev: Sha256Hash} => {
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
const fetchSigChain = async (h: Sha256Hash, uid: Uid): Promise<ChainLinkJSON[]> => {
  const url = keybaseAPIServerURI + 'sig/get.json?uid=' + uid
  const response = await axios.get(url)
  const sigs = response.data.sigs
  const numSigs = sigs.length
  const ret: ChainLinkJSON[] = []
  let expectedHash = h
  for (let i = numSigs - 1; i >= 0; i--) {
    const {payload, prev} = checkLink(sigs[i], expectedHash, i)
    expectedHash = prev
    ret.push(payload)
  }
  return ret.reverse()
}

export {Uid}

// checkUid traverses the stellar root down to the given Uid, and returns the
// full sigchain of the user. This function is kept simple for the basis
// of site documentation.
export const checkUid = async (uid: Uid): Promise<ChainLinkJSON[]> => {
  const rootHash = await fetchLatestRootHashFromStellar()
  const pathFromRoot = await fetchPathFromRoot(rootHash, uid)
  const sigPayload = await checkSigAgainstStellar(pathFromRoot, rootHash)
  const rootNodeHash = extractRootFromSigPayload(sigPayload)
  const chainTail = walkPathToLeaf(pathFromRoot, rootNodeHash, uid)
  const chain = await fetchSigChain(chainTail, uid)
  return chain
}
