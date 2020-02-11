import {URLSearchParams} from 'url'
import axios from 'axios'
import {keybaseAPIServerURI} from './constants'
import {Uid, Kid, Sha256Hash, Sha512Hash} from './types'
import {verify} from 'kbpgp'
import {sha256} from './util'

export class Key {
  raw: string
  kid: Kid
  key: verify.GenericKey
  fullHash: Sha256Hash

  constructor(k: verify.GenericKey, r: string) {
    this.key = k
    this.kid = k.kid() as Kid
    this.raw = r
    this.fullHash = sha256(Buffer.from(r, 'ascii')) as Sha256Hash
  }
}

export class KeyRing {
  uid: Uid
  byKid: Map<Kid, Key>
  byFullHash: Map<Sha256Hash, Key>

  constructor(u: Uid) {
    this.uid = u
    this.byKid = new Map<Kid, Key>()
    this.byFullHash = new Map<Sha256Hash, Key>()
  }

  async parseKey(s: string): Promise<void> {
    const vk = await verify.importKey(s)
    const key = new Key(vk, s)
    this.byKid.set(key.kid, key)
    if (vk.isPGP()) {
      this.byFullHash.set(key.fullHash, key)
    }
  }

  async fetch(): Promise<void> {
    const params = new URLSearchParams({uid: this.uid})
    const url = keybaseAPIServerURI + 'user/lookup.json?' + params.toString()
    const response = await axios.get(url)
    const keys = response.data.them.public_keys.all_bundles as string[]
    for (const raw of keys) {
      this.parseKey(raw)
    }
    return
  }
}
