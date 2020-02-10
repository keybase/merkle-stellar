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
  skips?: string[]
}

export type ResetChainTail = [number, Sha512Hash]

export type UserSigChain = {
  links: ChainLinkBundle[]
  resets: ResetChain | null
  maxes: ChainMaxes
  eldest: Kid | null
  uid: Uid
}

export type SigChainTail = [
  number, // Publiic Seqno
  Sha256Hash, // Public Tail Link Hash
  Sha256Hash // Public Tail Sig Hash
]

export type ChainTails = [
  number, // version
  SigChainTail, // public SigChainTail
  [],
  Kid | null, // Eldest Key Id or null if a reset account
  ResetChainTail | null
]

export type ChainLinkJSON = {
  body: {
    type: string
    key: {
      eldest_kid?: Kid
      kid: Kid
      uid: Uid
    }
    version: number
  }
  ctime: number
  prev: Sha256Hash
  seqno: number
  tag: 'signature'
}

export type ChainLinkBundle = {
  inner: ChainLinkJSON
  outer: Sig2Payload
  sig: string
}

export type TreeRoots = {
  body: {
    root: Sha512Hash
    legacy_uid_root: Sha256Hash
    seqno: number
    skips?: {
      [key: string]: Sha256Hash
    }
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

export type RawLinkJSON = {
  payload_json: string
  sig: string
  sig_version: number
}

export type Sig2Payload = [number, number, Uint8Array, Uint8Array, number, number, boolean]

export type Device = {
  name: string
  type: 'desktop' | 'mobile' | 'backup'
  enc: Kid
  sig: Kid
}

export type UserKeys = {
  puk?: Kid
  devices: Device[]
}

export class ChainMaxes {
  sig: number
  merkle: number
  stellar: number

  isFresh(): boolean {
    return this.sig == this.merkle && this.merkle == this.stellar
  }

  constructor(arg: {sig: number; merkle: number; stellar: number}) {
    this.sig = arg.sig
    this.merkle = arg.merkle
    this.stellar = arg.stellar
  }

  generateWarning(): string[] {
    if (this.isFresh()) {
      return []
    }
    const ret: string[] = []
    if (this.sig > this.merkle) {
      ret.push(`Merkle tree is behind sigchain: ${this.sig} > ${this.merkle}`)
    }
    if (this.merkle > this.stellar) {
      ret.push(`Merkle tree is behind the Stellar blockchain: ${this.merkle} > ${this.stellar}`)
    }
    return ret
  }
}
