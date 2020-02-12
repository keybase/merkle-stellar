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
export type DeviceId = NominalType<string, 'deviceId'>
export type SigId = NominalType<string, 'sigId'>
export type SigIdMapKey = NominalType<string, 'sigIdMapKey'>

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

export type RevokeJSON = {
  sig_id?: SigId
  sig_ids?: SigId[]
  kid: Kid
  kids?: Kid[]
}

export type DeviceType = 'mobile' | 'backup' | 'desktop'

export type DeviceJSON = {
  id: DeviceId
  name: string
  type: DeviceType
}

export type SibkeyJSON = {
  kid: Kid
  reverse_sig: string
}

export type SubkeyJSON = {
  kid: Kid
  parent_kid: Kid
}

export type PerUserKeyJSON = {
  encryption_kid: Kid
  generation: number
  signing_kid: Kid
  reverse_sig: string
}

export type PgpUpdateJSON = {
  full_hash: Sha256Hash
  kid: Kid
}

export type ChainLinkJSON = {
  body: {
    type: string
    key: {
      eldest_kid?: Kid
      kid: Kid
      uid: Uid
    }
    revoke?: RevokeJSON
    device?: DeviceJSON
    version: number
    sibkey?: SibkeyJSON
    subkey?: SubkeyJSON
    pgp_update?: PgpUpdateJSON
    per_user_key?: PerUserKeyJSON
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
  kid: Kid
  payloadHash: Sha256Hash
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
  kid: Kid
}

export type Sig2Payload = [number, number, Uint8Array, Uint8Array, number, number, boolean]

export type EncSigPair = {
  enc: Kid
  sig: Kid
}

export type PerUserKey = {
  keys: EncSigPair
  generation: number
}

export const perUserKeyFromJSON = (p: PerUserKeyJSON): PerUserKey => {
  return {
    keys: {sig: p.signing_kid, enc: p.encryption_kid} as EncSigPair,
    generation: p.generation,
  } as PerUserKey
}

export type Device = {
  name: string
  id: DeviceId
  type: DeviceType
  keys: EncSigPair
}

export const deviceFromJSON = (d: DeviceJSON, sigKid: Kid): Device => {
  return {name: d.name, id: d.id, type: d.type, keys: {sig: sigKid} as EncSigPair} as Device
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
