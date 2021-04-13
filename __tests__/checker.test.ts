import {Uid} from '../lib/types'
import {Checker} from '../lib'

test('Can fetch user max from the tree by UID', async (): Promise<void> => {
  const chk = new Checker()
  const ret = await chk.checkUid('dbb165b7879fe7b1174df73bed0b9500' as Uid)
  expect(ret.length).toBeGreaterThanOrEqual(691)
})

test('Can fetch user max from the tree by username', async (): Promise<void> => {
  const chk = new Checker()
  const ret = await chk.checkUsername('max' as Uid)
  expect(ret.length).toBeGreaterThanOrEqual(691)
})
