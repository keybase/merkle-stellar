import {createHash} from 'crypto'
import {Sha256Hash} from './types'

export const sha256 = (b: Buffer): Sha256Hash => {
  return createHash('sha256')
    .update(b)
    .digest('hex') as Sha256Hash
}
