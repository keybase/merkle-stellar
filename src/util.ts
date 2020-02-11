import {createHash} from 'crypto'
import {Sha256Hash, SigId, SigIdMapKey} from './types'

export const sha256 = (b: Buffer): Sha256Hash => {
  return createHash('sha256')
    .update(b)
    .digest('hex') as Sha256Hash
}

export const sigIdToMapKey = (s: SigId): SigIdMapKey => {
  let tmp = s as string
  if (tmp.length == 66) {
    const sffx = tmp.slice(64, 66)
    if (sffx == '0f' || sffx == '22') {
      tmp = tmp.slice(0, 64)
    }
  }
  if (tmp.length != 64) {
    throw new Error(`bad sig ID found ${tmp}`)
  }
  return tmp as SigIdMapKey
}
