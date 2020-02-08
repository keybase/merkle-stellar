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

export type ResetChain = Array<ResetChainLinkJSON>

export type ResetChainLinkJSON = {
  ctime: number
  merkle_root: {
    hash_meta: Sha256Hash
    seqno: number
  }
  prev: {
    eldest_kid: Kid
    public_seqno: number
    reset: Sha512Hash | null
  }
  reset_seqno: number
  type: 'reset' | 'delete'
  uid: Uid
}

export type PathAndSigsJSON = {
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
  reset_chain?: string[]
}

export type ResetChainTail = [number, Sha512Hash]

export type UserSigChain = {
  links: ChainLinkJSON[]
  resets: ResetChain | null
}

export type ChainTail = [
  number, // version
  [
    number, // Publiic Seqno
    Sha256Hash, // Public Tail Link Hash
    Sha256Hash // Public Tail Sig Hash
  ],
  [],
  Kid | null, // Eldest Key Id or null if a reset account
  ResetChainTail | null
]

export type ChainLinkJSON = {
  body: {
    type: string
  }
  ctime: number
  prev: Sha256Hash
  seqno: number
  tag: 'signature'
}

export type TreeRoots = {
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
