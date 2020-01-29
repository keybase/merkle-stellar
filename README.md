# merkle-stellar

[![Travis CI](https://travis-ci.org/keybase/merkle-stellar.svg?branch=master)](https://travis-ci.org/keybase/merkle-stellar)

Library to read Merkle root out of Stellar blockchain.

## Install

```
$ npm i -g keybase-merkle-stellar
```

## Demo

```
$ keybase-merkle-stellar-check max
✔ 1. fetch latest root from stellar: returned #27980338, closed at 2020-01-29T13:00:06Z
✔ 2. fetch keybase path from root for max: got back seqno #14406067
✔ 3. check hash equality for 070202749f229c2b6a99bac9fd8fe8a0e429dc266c2e9dff2dbc51e0fe190a09: match
✔ 4. extract UID for max: map to dbb165b7879fe7b1174df73bed0b9500 via legacy tree
✔ 5. walk path to leaf for dbb165b7879fe7b1174df73bed0b9500: tail hash is 913358757a2e1c36cb17e70b4bc51496829e97179509f854f18641d80e57637f
✔ 6. fetch sigchain from keybase for dbb165b7879fe7b1174df73bed0b9500: got back 691 links
```

## The Code

The main operations can be found in the [Checker](./src/check.ts) class:

```TypeScript
  // checkUsername traverses the stellar root down to the given username, and returns the
  // full sigchain of the user. This function is kept simple for the basis
  // of site documentation.
  async checkUsername(username: string): Promise<ChainLinkJSON[]> {
    const metaHash = await this.fetchLatestMetaHashFromStellar()
    const metadataAndPath = await this.fetchMetadataAndPathForUsername(metaHash, username)
    const treeRoots = await this.checkSigAgainstStellar(metadataAndPath, metaHash)
    const uid = this.extractUid(username, metadataAndPath, treeRoots.body.legacy_uid_root)
    const chainTail = this.walkPathToLeaf(metadataAndPath, treeRoots.body.root, uid)
    const chain = await this.fetchSigChain(chainTail, uid)
    return chain
  }
```
