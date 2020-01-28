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
