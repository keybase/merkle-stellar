import axios, {AxiosRequestConfig, AxiosInstance} from 'axios'

jest.mock('axios')
import {apiMock} from './api_mock'

const mockedAxios = axios as jest.Mocked<typeof axios>

// The Stellar toolkit uses a static Axios object with interceptors,
// so we need to mock out more of the object than usual.
mockedAxios.create.mockImplementation(
  (): AxiosInstance => {
    return {
      interceptors: {
        response: {
          use: (): void => {},
        },
      },
      get: async (url: string): Promise<unknown> => {
        return apiMock(url)
      },
    } as AxiosInstance
  }
)

mockedAxios.get.mockImplementation(
  (url: string, config?: AxiosRequestConfig): Promise<unknown> => {
    return apiMock(url)
  }
)

import {Uid} from '../lib/types'
import {TreeWalker} from '../lib'

test('Can fetch user max from the tree by UID', async (): Promise<void> => {
  const tw = new TreeWalker()
  const ret = await tw.walkUid('dbb165b7879fe7b1174df73bed0b9500' as Uid)
  expect(ret.links.length).toBe(691)
  expect(ret.resets).toBeNull()
  expect(ret.maxes.isFresh()).toBe(true)
})

test('Can fetch user max from the tree by username', async (): Promise<void> => {
  const tw = new TreeWalker()
  const ret = await tw.walkUsername('max')
  expect(ret.links.length).toBe(691)
  expect(ret.resets).toBeNull()
  expect(ret.maxes.isFresh()).toBe(true)
})

test('Can fetch user zanderz from the tree by username and check has resets', async (): Promise<void> => {
  const tw = new TreeWalker()
  const ret = await tw.walkUsername('zanderz')
  expect(ret.links.length).toBe(271)
  expect(ret.resets.length).toBe(1)
  expect(ret.maxes.isFresh()).toBe(true)
})

test('Can replay a long reset chain', async (): Promise<void> => {
  const tw = new TreeWalker()
  const ret = await tw.walkUid('10286214005a3b5c1c284b7374e97c19' as Uid)
  expect(ret.links.length).toBe(138)
  expect(ret.resets.length).toBe(8)
  expect(ret.maxes.isFresh()).toBe(true)
})

// Here the stellar root is about a week behind the live root, and there were
// ~6 sigs in between. Test can use some more assertions.
test('Can replay skips when loading mikem', async (): Promise<void> => {
  const tw = new TreeWalker()
  const ret = await tw.walk('mikem')
  expect(ret.links.length).toBe(574)
  expect(ret.resets).toBeNull()
  expect(ret.maxes.isFresh()).toBe(false)
})
