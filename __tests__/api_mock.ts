const apiMockDataFile = (url: string): string | null => {
  if (
    url.indexOf('https://horizon.stellar.org/accounts/GA72FQOMHYUCNEMZN7GY6OBWQTQEXYL43WPYCY2FE3T452USNQ7KSV6E/transactions?order=desc') ==
    0
  ) {
    return './data/horizon.json'
  }
  if (url.indexOf('https://horizon.stellar.org/ledgers/27966265') == 0) {
    return './data/ledger.json'
  }
  const tab: {[key: string]: any} = {
    'https://keybase.io/_/api/1.0/merkle/path.json?uid=dbb165b7879fe7b1174df73bed0b9500&start_hash256=2dd5285fe116e8cc3a70f026338b7373c486d1229d0f97d8b2027c70db4707ac&last=14393662&load_reset_chain=1':
      './data/path_by_uid_max.json',
    'https://keybase.io/_/api/1.0/merkle/path.json?uid=dbb165b7879fe7b1174df73bed0b9500&load_reset_chain=1': './data/path_by_uid_max.json',
    'https://keybase.io/_/api/1.0/sig/get.json?uid=dbb165b7879fe7b1174df73bed0b9500': './data/sigs_for_max.json',
    'https://keybase.io/_/api/1.0/merkle/path.json?username=max&load_reset_chain=1': './data/path_by_username_max.json',
    'https://keybase.io/_/api/1.0/merkle/path.json?username=zanderz&load_reset_chain=1': './data/path_by_username_zanderz.json',
    'https://keybase.io/_/api/1.0/merkle/path.json?uid=673a740cd20fb4bd348738b16d228219&start_hash256=2dd5285fe116e8cc3a70f026338b7373c486d1229d0f97d8b2027c70db4707ac&last=14393662&load_reset_chain=1':
      './data/path_by_username_zanderz.json',
    'https://keybase.io/_/api/1.0/sig/get.json?uid=673a740cd20fb4bd348738b16d228219': './data/sigs_for_zanderz.json',
    'https://keybase.io/_/api/1.0/merkle/path.json?uid=10286214005a3b5c1c284b7374e97c19&load_reset_chain=1':
      './data/path_by_uid_bitn3ss.json',
    'https://keybase.io/_/api/1.0/merkle/path.json?uid=10286214005a3b5c1c284b7374e97c19&start_hash256=2dd5285fe116e8cc3a70f026338b7373c486d1229d0f97d8b2027c70db4707ac&last=14393662&load_reset_chain=1':
      './data/path_by_uid_bitn3ss.json',
    'https://keybase.io/_/api/1.0/sig/get.json?uid=10286214005a3b5c1c284b7374e97c19': './data/sigs_for_bitn3ss.json',
    'https://keybase.io/_/api/1.0/merkle/path.json?username=mikem&load_reset_chain=1': './data/path_by_username_mikem.json',
    'https://keybase.io/_/api/1.0/merkle/path.json?uid=95e88f2087e480cae28f08d81554bc00&start_hash256=2dd5285fe116e8cc3a70f026338b7373c486d1229d0f97d8b2027c70db4707ac&last=14553487&load_reset_chain=1':
      './data/path_by_uid_historical_mikem.json',
    'https://keybase.io/_/api/1.0/sig/get.json?uid=95e88f2087e480cae28f08d81554bc00': './data/sigs_for_mikem.json',
  }
  const ret = tab[url]
  if (ret) {
    return ret
  }
}

const apiMockData = (url: string): any => {
  const file = apiMockDataFile(url)
  if (!file) {
    throw new Error(`unhandled mock API call ${url}`)
  }
  return require(file)
}

export const apiMock = (url: string): Promise<unknown> => {
  const data = apiMockData(url)
  return Promise.resolve({data: data})
}
