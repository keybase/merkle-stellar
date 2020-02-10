import {URLSearchParams} from 'url'
import axios from 'axios'
import {keybaseAPIServerURI} from './constants'
import {Uid, Kid} from './types'
import {verify} from 'kbpgp'

export class Key {
  raw: string
  kid: Kid
  key: verify.GenericKey
}

export class KeyRing {
  uid: Uid

  constructor(u: Uid) {
    this.uid = u
  }

  async fetch(): Promise<void> {}
}
