import {checkUid} from '../lib'
import {Uid} from '../lib/types'

test('Can fetch user max from the tree', async (): Promise<void> => {
  const ret = await checkUid('dbb165b7879fe7b1174df73bed0b9500' as Uid)
  expect(ret.length).toBeGreaterThanOrEqual(691)
})
