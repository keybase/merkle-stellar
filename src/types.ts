export class NominalTypeTag<TId> {
  constructor() {
    this._type
  }
  private _type: TId | undefined
}
export type NominalType<T, TId> = T & NominalTypeTag<TId>

export type Uid = NominalType<string, 'uid'>
export type Kid = NominalType<string, 'kid'>
export type Username = NominalType<string, 'username'>
export type Sha256Hash = NominalType<string, 'sha256hash'>
export type Sha512Hash = NominalType<string, 'sha512hash'>
export type StellarPublicKey = NominalType<string, 'stellarPublicKey'>

export type PathNodeJSON = {
  prefix: string
  node: {
    hash: Sha512Hash
    val: string
    type: number
  }
}

export type PathFromRootJSON = {
  status: {
    code: number
    desc?: string
  }
  root: {
    sigs: {[key: string]: {sig: string}}
    seqno: number
  }
  path: PathNodeJSON[]
  uid: Uid
  username: string
  uid_proof_path?: PathNodeJSON[]
}

export type ChainLinkJSON = {
  body: {
    type: string
  }
  ctime: number
  prev: Sha256Hash
  seqno: number
  tag: 'signature'
}

export type RootSigPayload = {
  body: {
    root: Sha512Hash
    legacy_uid_root: Sha256Hash
  }
}

export type KeybaseSig = {
  body: {
    detached: boolean
    hash_type: 10
    key: Buffer
    payload: Buffer
    sig: Buffer
    sig_type: number
  }
  tag: number
  version: 1
}

export type Sig2Payload = [number, number, Uint8Array, Uint8Array, number, number, boolean]
