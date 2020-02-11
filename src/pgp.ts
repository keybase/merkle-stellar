import {URLSearchParams} from 'url'
import axios from 'axios'
import {keybaseAPIServerURI} from './constants'
import {Uid, Kid, Sha256Hash, Sha512Hash} from './types'
import {verify} from 'kbpgp'
import {sha256} from './util'

interface GenericKey {
  verify(s: string): Promise<Buffer>
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
}

export class PGPKeySet implements GenericKey {
  kid: Kid
  byFullHash: Map<Sha256Hash, PGPKey>
  current: Sha256Hash | null

  constructor(k: verify.GenericKey, r: string) {
    this.kid = k.kid() as Kid
    const key = new PGPKey(k, r)
    this.byFullHash = new Map<Sha256Hash, PGPKey>()
    this.insert(key)
  }

  insert(key: PGPKey) {
    this.byFullHash.set(key.fullHash, key)
  }

  select(h: Sha256Hash) {
    this.current = h
  }

  async verify(s: string): Promise<Buffer> {
    if (this.current) {
      const key = this.byFullHash.get(this.current)
      const ret = await key.key.verify(s)
      return ret
    }

    for (const key of this.byFullHash.values()) {
      try {
        const ret = await key.key.verify(s)
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

  async verify(s: string): Promise<Buffer> {
    const ret = await this.key.verify(s)
    return ret
  }
}

export class KeyRing {
  uid: Uid
  byKid: Map<Kid, GenericKey>
  pgpKeys: Map<Kid, PGPKeySet>

  constructor(u: Uid) {
    this.uid = u
    this.byKid = new Map<Kid, GenericKey>()
    this.pgpKeys = new Map<Kid, PGPKeySet>()
  }

  addPgpKey(vk: verify.GenericKey, raw: string) {
    const kid = vk.kid() as Ki
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

  async addKey(s: string): Promise<void> {
    const vk = await verify.importKey(s)
    if (vk.isPGP()) {
      return this.addPgpKey(vk, s)
    }
    const key = new NaClKey(vk)
    this.byKid.set(key.kid, key)
    return
  }

  async verify(kid: Kid, sig: string): Promise<Buffer> {
    const key = this.byKid.get(kid)
    if (!key) {
      throw new Error('key not found in keyring')
    }
    const ret = await key.verify(sig)
    return ret
  }

  async fetch(): Promise<void> {
    const params = new URLSearchParams({uid: this.uid})
    const url = keybaseAPIServerURI + 'user/lookup.json?' + params.toString()
    const response = await axios.get(url)
    const keys = response.data.them.public_keys.all_bundles as string[]
    for (const raw of keys) {
      this.addKey(raw)
    }
    return
  }
}
