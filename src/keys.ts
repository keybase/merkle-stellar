import {URLSearchParams} from 'url'
import axios from 'axios'
import {keybaseAPIServerURI} from './constants'
import {
  Uid,
  Kid,
  Sha256Hash,
  DeviceId,
  Device,
  SigIdMapKey,
  RevokeJSON,
  SigId,
  EncSigPair,
  DeviceJSON,
  deviceFromJSON,
  PerUserKeyJSON,
  PerUserKey,
  Sha512Hash,
} from './types'
import {verify} from 'kbpgp'
import {sha256, sigIdToMapKey} from './util'
import {Reporter, newReporter} from './reporter'
import chalk = require('chalk')

interface GenericKey {
  verify(s: string): Promise<[Buffer, Buffer]>
}

export class PGPKey {
  raw: string
  key: verify.GenericKey
  fullHash: Sha256Hash

  constructor(k: verify.GenericKey, r: string) {
    this.raw = r
    this.key = k
    this.fullHash = sha256(Buffer.from(r, 'ascii')) as Sha256Hash
  }

  async verify(s: string): Promise<[Buffer, Buffer]> {
    const opts = {time_travel: true, now: 1} as verify.Opts
    return this.key.verify(s, opts)
  }
}

export class PGPKeySet implements GenericKey {
  kid: Kid
  byFullHash: Map<Sha256Hash, PGPKey>
  last: PGPKey
  current: Sha256Hash | null

  constructor(k: verify.GenericKey, r: string) {
    this.kid = k.kid() as Kid
    const key = new PGPKey(k, r)
    this.byFullHash = new Map<Sha256Hash, PGPKey>()
    this.insert(key)
  }

  insert(key: PGPKey) {
    this.byFullHash.set(key.fullHash, key)
    this.last = key
  }

  select(h: Sha256Hash) {
    const k = this.byFullHash.get(h)
    if (!k) {
      throw new Error("cannot select PGP key in update, didn't have it in keyring")
    }
    this.current = h
  }

  exportKey(): string {
    let key = this.last
    if (this.current) {
      key = this.byFullHash.get(this.current)
    }
    return key.raw
  }

  async verify(s: string): Promise<[Buffer, Buffer]> {
    if (this.current) {
      const key = this.byFullHash.get(this.current)
      const ret = await key.verify(s)
      return ret
    }

    for (const key of this.byFullHash.values()) {
      try {
        const ret = await key.verify(s)
        return ret
      } catch (e) {}
    }
    throw new Error('could not verify with given PGP keys')
  }
}

export class NaClKey implements GenericKey {
  key: verify.GenericKey
  kid: Kid

  constructor(k: verify.GenericKey) {
    this.key = k
    this.kid = k.kid() as Kid
  }

  async verify(s: string): Promise<[Buffer, Buffer]> {
    const ret = await this.key.verify(s)
    return ret
  }
}

export class KeyRing {
  uid: Uid
  byKid: Map<Kid, GenericKey>
  pgpKeys: Map<Kid, PGPKeySet>
  reporter: Reporter

  constructor(u: Uid, r?: Reporter) {
    this.reporter = newReporter(r)
    this.uid = u
    this.byKid = new Map<Kid, GenericKey>()
    this.pgpKeys = new Map<Kid, PGPKeySet>()
  }

  selectPgpKey(k: Kid, h: Sha256Hash) {
    const key = this.pgpKeys.get(k)
    if (!key) {
      throw new Error('cannot select PGP key, KID not found')
    }
    key.select(h)
  }

  addPgpKey(vk: verify.GenericKey, raw: string) {
    const kid = vk.kid() as Kid
    const ks = this.pgpKeys.get(kid)
    if (ks) {
      const key = new PGPKey(vk, raw)
      ks.insert(key)
      return
    }
    const newKeySet = new PGPKeySet(vk, raw)
    this.pgpKeys.set(kid, newKeySet)
    this.byKid.set(kid, newKeySet)
    return
  }

  exportPgpKey(k: Kid): string | null {
    const key = this.pgpKeys.get(k)
    if (!key) {
      return null
    }
    return key.exportKey()
  }

  async addKey(s: string): Promise<void> {
    const vk = await verify.importKey(s, {time_travel: true})
    if (vk.isPGP()) {
      return this.addPgpKey(vk, s)
    }
    const key = new NaClKey(vk)
    this.byKid.set(key.kid, key)
    return
  }

  async verify(kid: Kid, sig: string): Promise<[Buffer, SigId]> {
    const key = this.byKid.get(kid)
    if (!key) {
      throw new Error('key not found in keyring')
    }
    const [payload, raw] = await key.verify(sig)
    const sigId = (sha256(raw) as string) as SigId
    return [payload, sigId]
  }

  async fetch(): Promise<void> {
    const reporter = this.reporter.step(`fetch all public keys from ${chalk.bold('keybase')}`)
    const params = new URLSearchParams({uid: this.uid})
    const url = keybaseAPIServerURI + 'user/lookup.json?' + params.toString()
    reporter.start(`contact ${chalk.grey(url)}`)
    const response = await axios.get(url)
    const keys = response.data.them.public_keys.all_bundles as string[]
    for (const raw of keys) {
      await this.addKey(raw)
    }
    reporter.success(`got ${keys.length} keys`)
    return
  }
}

export const isNaClSigKey = (kid: Kid): boolean => kid.slice(0, 4) == '0120'
export const isNaClEncKey = (kid: Kid): boolean => kid.slice(0, 4) == '0121'
export const isPgpKey = (kid: Kid): boolean => !isNaClSigKey(kid) || !isNaClEncKey(kid)

export class KeyFamily {
  uid: Uid
  devices: Map<DeviceId, Device>
  pgps: Set<Kid>
  byKid: Map<Kid, DeviceId>
  bySig: Map<SigIdMapKey, Kid[]>
  puk?: PerUserKey
  eldest: Kid

  constructor(u: Uid, eldest: Kid) {
    this.uid = u
    this.eldest = eldest
    this.devices = new Map<DeviceId, Device>()
    this.pgps = new Set<Kid>()
    this.byKid = new Map<Kid, DeviceId>()
    this.bySig = new Map<SigIdMapKey, Kid[]>()
  }

  revokeDevice(deviceId: DeviceId, kid: Kid) {
    const device = this.devices.get(deviceId)
    if (device && device.keys.sig == kid) {
      this.devices.delete(deviceId)
    }
  }

  addNaClSibkey(k: Kid, sig: SigId, d: DeviceJSON) {
    this.bySig.set(sigIdToMapKey(sig), [k])
    const device = deviceFromJSON(d, k)
    this.byKid.set(k, device.id)
    this.devices.set(device.id, device)
  }

  addNaClSubkey(k: Kid, sigId: SigId, d: DeviceJSON) {
    const mapKey = sigIdToMapKey(sigId)
    const device = this.devices.get(d.id)
    if (device) {
      device.keys.enc = k
    }
    this.byKid.set(k, d.id)
    this.bySig.set(mapKey, [k])
  }

  addPerUserKey(puk: PerUserKey, sigId: SigId) {
    this.puk = puk
    const mapKey = sigIdToMapKey(sigId)
    this.bySig.set(mapKey, [puk.keys.sig, puk.keys.enc])
  }

  addPgpSibkey(k: Kid, sig: SigId) {
    this.bySig.set(sigIdToMapKey(sig), [k])
    this.pgps.add(k)
  }

  addPgpEldestKey(k: Kid) {
    this.pgps.add(k)
  }

  isActive = (kid: Kid): boolean => this.pgps.has(kid) || !!this.byKid.get(kid)

  revokeKey(kid: Kid) {
    const deviceId = this.byKid.get(kid)
    if (deviceId) {
      this.revokeDevice(deviceId, kid)
      this.byKid.delete(kid)
    }
    const pgpKey = this.pgps.has(kid)
    if (pgpKey) {
      this.pgps.delete(kid)
    }
    if (this.puk && (this.puk.keys.enc == kid || this.puk.keys.sig == kid)) {
      this.puk = null
    }
  }

  revokeSig(sigID: SigId) {
    const mapKey = sigIdToMapKey(sigID)
    const kids = this.bySig.get(mapKey)
    if (!kids || kids.length == 0) {
      return
    }
    for (const kid of kids) {
      this.revokeKey(kid)
    }
    this.bySig.delete(mapKey)
  }

  revokeBatch(revokes: RevokeJSON | null) {
    if (!revokes) {
      return
    }
    if (revokes.sig_id) {
      this.revokeSig(revokes.sig_id)
    }
    for (const sig of revokes.sig_ids || []) {
      this.revokeSig(sig)
    }
    if (revokes.kid) {
      this.revokeKey(revokes.kid)
    }
    for (const key of revokes.kids || []) {
      this.revokeKey(key)
    }
  }
  summary(): string {
    return [
      `PUK generation: ${this.puk?.generation || 'n/a'}`,
      `live devices: ${this.devices.size}`,
      `live PGP keys: ${this.pgps.size}`,
    ].join('; ')
  }
}

export class UserKeys {
  puk?: PerUserKey
  devices: Device[]
  pgpKeys: string[]

  constructor(r: KeyRing, f: KeyFamily) {
    this.puk = f.puk
    this.devices = Array.from(f.devices.values())
    this.pgpKeys = Array.from(f.pgps.keys()).map((kid: Kid) => r.exportPgpKey(kid))
  }
}
