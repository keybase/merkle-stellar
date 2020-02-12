import {
  UserSigChain,
  ChainLinkJSON,
  DeviceJSON,
  Kid,
  Uid,
  ChainLinkBundle,
  RevokeJSON,
  SigId,
  SibkeyJSON,
  SubkeyJSON,
  PerUserKeyJSON,
  EncSigPair,
  perUserKeyFromJSON,
  PgpUpdateJSON,
} from './types'
import {KeyRing as Keyring, KeyFamily, isNaClSigKey, isPgpKey, UserKeys} from './keys'
import {sha256} from './util'
import kbpgp from 'kbpgp'
import {Reporter, newReporter} from './reporter'
import chalk from 'chalk'
import {promisify} from 'util'

function timeout(ms: number) {
  return new Promise(resolve => setTimeout(resolve, ms))
}

class ChainLink {
  json: ChainLinkJSON
  constructor(j: ChainLinkJSON) {
    this.json = j
  }

  eldestKid = (): Kid | null => this.json.body.key.eldest_kid || this.json.body.key.kid
  uid = (): Uid => this.json.body.key.uid
  seqno = (): number => this.json.seqno
  type = (): string => this.json.body.type
  isEldest = (): boolean => this.type() == 'eldest'
  sigVersion = (): number => this.json.body.version
  revokes = (): RevokeJSON | null => this.json.body.revoke
  device = (): DeviceJSON | null => this.json.body.device
  sibkey = (): SibkeyJSON | null => this.json.body.sibkey
  subkey = (): SubkeyJSON | null => this.json.body.subkey
  perUserKey = (): PerUserKeyJSON | null => this.json.body.per_user_key
  pgpUpdate = (): PgpUpdateJSON | null => this.json.body.pgp_update

  sibkeyPayloadWithNulledReverseSig = (): string => {
    const rs = this.json.body.sibkey?.reverse_sig
    if (!rs) {
      throw new Error('no reverse sig slot to null out')
    }
    this.json.body.sibkey.reverse_sig = null
    const ret = kbpgp.util.json_stringify_sorted(this.json)
    this.json.body.sibkey.reverse_sig = rs
    return ret
  }

  perUserKeyPayloadWithNulledReverseSig = (): string => {
    const rs = this.json.body.per_user_key?.reverse_sig
    if (!rs) {
      throw new Error('no reverse sig slot to null out')
    }
    this.json.body.per_user_key.reverse_sig = null
    const ret = kbpgp.util.json_stringify_sorted(this.json)
    this.json.body.per_user_key.reverse_sig = rs
    return ret
  }
}

class BundleWrapper {
  bundle: ChainLinkBundle
  link: ChainLink
  constructor(b: ChainLinkBundle) {
    this.bundle = b
    this.link = new ChainLink(b.inner)
  }

  async verify(kr: Keyring): Promise<[Kid, SigId]> {
    const kid = this.bundle.kid
    const [payload, sigId] = await kr.verify(kid, this.bundle.sig)
    const verifiedHash = sha256(payload)
    if (verifiedHash != this.bundle.payloadHash) {
      throw new Error("verified payload didn't match expectations")
    }
    return [kid, sigId]
  }
}

const hardcodedResets: {[key: string]: number} = {
  '2d5c41137d7d9108dbdaa2160ba7e200': 11,
  f1c263462dd526695c458af924977719: 8,
  '8dbf0f1617e285befa93d3da54b68419': 8,
  '372c1cbd72e4f851a74d232478a72319': 2,
  '12e124d5d1ff6179f3aab88100b93d19': 5,
  a07089770463db10994c8727177eef19: 12,
}

const isEmpty = (c: Array<any>): boolean => !c || c.length == 0

export class Player {
  reporter: Reporter

  constructor(r?: Reporter) {
    this.reporter = newReporter(r)
  }

  // When we're *in the middle of a subchain* (see the note below), there are
  // four ways we can tell that a link is the start of a new subchain:
  // 1) The link is seqno 1, the very first link the user ever makes.
  // 2) The link has the type "eldest". Modern seqno 1 links and sigchain resets
  //    take this form, but old ones don't.
  // 3) The link has a new eldest kid relative to the one that came before. In
  //    the olden days, all sigchain resets were of this form. Note that oldest
  //    links didn't have the eldest_kid field at all, so the signing kid was
  //    assumed to be the eldest.
  // 4) One of a set of six hardcoded links that made it in back when case 3 was
  //    the norm, but we forgot to prohibit reusing the same eldest key. We figured
  //    out this set from server data, once we noticed the mistake.
  //
  // Note: This excludes cases where a subchain has length zero, either because
  // the account is totally new, or because it just did a reset but has no new
  // links (as reflected in the eldest kid we get from the merkle tree).
  // Different callers handle those cases differently. (Loading the sigchain from
  // local cache happens before we get the merkle leaf, for example, and so it
  // punts reset-after-latest-link detection to the server loading step).
  isSubchainStart(c: ChainLinkJSON, p: ChainLinkJSON): boolean {
    const curr = new ChainLink(c)
    const prev = new ChainLink(p)
    const uid = curr.uid()
    if (uid != prev.uid()) {
      throw new Error('uid mismatch on two adjacent links')
    }

    // case 1 -- unlikely to be hit in practice, because prevLink would be nil
    if (curr.seqno() == 1) {
      return true
    }

    // case 2
    if (curr.isEldest()) {
      return true
    }
    // case 2.5: The signatures in cases 3 and 4 are very old, from long before
    // v2 sigs were introduced. If either the current or previous sig is v2,
    // short circuit here. This is important because stubbed links (introduced
    // with v2) break the eldest_kid check for case 3.
    if (curr.sigVersion() > 1 || prev.sigVersion() > 1) {
      return false
    }

    // case 3
    if (curr.eldestKid() && prev.eldestKid() && curr.eldestKid() != prev.eldestKid()) {
      return true
    }

    // case 4
    const resetSeqno = hardcodedResets[uid]
    if (resetSeqno == curr.seqno()) {
      return true
    }

    return false
  }

  // cropToRightmostSubchain takes the given set of chain links, and then limits the tail
  // of the chain to just those that correspond to the eldest key given by `eldest`.
  cropToRightmostSubchain(chain: UserSigChain): ChainLinkBundle[] {
    const links = chain.links
    const eldest = chain.eldest
    const empty = [] as ChainLinkBundle[]
    if (links.length === 0) {
      return empty
    }

    // Check whether the eldest KID doesn't match the latest link. That means
    // the account has just been reset, and so as with a new account, there is
    // no current subchain.
    const lastLink = new ChainLink(links[links.length - 1].inner)
    const firstLink = new ChainLink(links[0].inner)
    if (lastLink.eldestKid() != eldest) {
      return empty
    }

    // The usual case: The eldest kid we're looking for matches the latest
    // link, and we need to loop backwards through every pair of links we have.
    // If we find a subchain start, return that subslice of links.
    for (let i = links.length - 1; i > 0; i--) {
      const curr = links[i].inner
      const prev = links[i - 1].inner
      const isStart = this.isSubchainStart(curr, prev)
      if (isStart) {
        return links.slice(i)
      }
    }
    // If we didn't find a start anywhere in the middle of the chain, then this
    // user has no resets, and we'll return the whole chain. Sanity check that
    // we actually loaded everything back to seqno 1. (Anything else would be
    // some kind of bug in chain loading.)
    if (firstLink.seqno() != 1) {
      throw new Error('chain ended unexpectedly before seqno 1 in GetCurrentSubchain')
    }

    // In this last case, we're returning the whole chain.
    return links
  }

  async playEldestLink(uid: Uid, firstRaw: ChainLinkBundle, keyring: Keyring, expectedEldest: Kid): Promise<KeyFamily> {
    const first = new BundleWrapper(firstRaw)
    const type = first.link.type()
    const device = first.link.device()
    const isEldestLink = type == 'eldest'
    const [eldestKid, sigId] = await first.verify(keyring)
    if (eldestKid != expectedEldest) {
      throw new Error('got wrong eldest Kid in first link')
    }
    const ret = new KeyFamily(uid, eldestKid)
    if (isNaClSigKey(eldestKid)) {
      if (!isEldestLink) {
        throw new Error('modern keys should have an eldest link at beginning of subchain')
      }
      ret.addNaClSibkey(eldestKid, sigId, device)
    } else if (isPgpKey(eldestKid)) {
      ret.addPgpEldestKey(eldestKid)
    }
    return ret
  }

  async playSibkey(link: BundleWrapper, sigId: SigId, keyring: Keyring, keyFamily: KeyFamily): Promise<void> {
    const sibkey = link.link.sibkey()
    if (!sibkey) {
      throw new Error('missing sibkey section')
    }
    const kid = sibkey.kid
    const reverseSig = sibkey.reverse_sig
    const [reversePayloadBuffer, _] = await keyring.verify(kid, reverseSig)
    const expected = link.link.sibkeyPayloadWithNulledReverseSig()
    if (reversePayloadBuffer.toString('ascii') != expected) {
      throw new Error('reverse payload mismatch after nulling out sig')
    }

    if (isNaClSigKey(kid)) {
      const device = link.link.device()
      keyFamily.addNaClSibkey(kid, sigId, device)
    } else if (isPgpKey(kid)) {
      keyFamily.addPgpSibkey(kid, sigId)
    } else {
      throw new Error('unexpected type of sibkey found')
    }

    return
  }

  playSubkey(link: BundleWrapper, sigId: SigId, keyFamily: KeyFamily): void {
    const subkey = link.link.subkey()
    if (!subkey) {
      throw new Error('missing sibkey section')
    }
    const kid = subkey.kid
    const device = link.link.device()
    keyFamily.addNaClSubkey(kid, sigId, device)
  }

  async playPgpUpdate(link: BundleWrapper, keyring: Keyring, keyFamily: KeyFamily): Promise<void> {
    const update = link.link.pgpUpdate()
    if (!update) {
      throw new Error('missing PGP update')
    }
    keyring.selectPgpKey(update.kid, update.full_hash)
    return
  }

  async playPerUserKey(link: BundleWrapper, sigId: SigId, keyring: Keyring, keyFamily: KeyFamily): Promise<void> {
    const pukJSON = link.link.perUserKey()
    if (!pukJSON) {
      throw new Error('missing per_user_key section')
    }
    const puk = perUserKeyFromJSON(pukJSON)
    const reverseSig = pukJSON.reverse_sig
    const verifyKey = await kbpgp.verify.importKey(puk.keys.sig, null)
    const [reversePayloadBuffer, _] = await verifyKey.verify(reverseSig, null)
    const expected = link.link.perUserKeyPayloadWithNulledReverseSig()
    if (reversePayloadBuffer.toString('ascii') != expected) {
      throw new Error('reverse sig mismatch in PUK after nulling out sig')
    }
    keyFamily.addPerUserKey(puk, sigId)
    return
  }

  async verifyLink(link: BundleWrapper, keyring: Keyring, keyFamily: KeyFamily): Promise<SigId> {
    const [kid, sigId] = await link.verify(keyring)
    if (!keyFamily.isActive(kid)) {
      throw new Error(`key wasn't active ${kid} for signature`)
    }
    return sigId
  }

  async playSubchain(uid: Uid, chain: ChainLinkBundle[], keyring: Keyring, expectedEldest: Kid | null): Promise<UserKeys | null> {
    if (isEmpty(chain)) {
      return null
    }
    if (!expectedEldest) {
      throw new Error('got an empty chain but we expected an eldest kid')
    }

    const reporter = this.reporter.step(`play sigchain for ${chalk.italic(uid)}`)
    reporter.start(`eldest key: ${expectedEldest}`)

    const keyFamily = await this.playEldestLink(uid, chain[0], keyring, expectedEldest)

    let i = 1
    for (const raw of chain.slice(1)) {
      const link = new BundleWrapper(raw)

      const sigId = await this.verifyLink(link, keyring, keyFamily)
      const type = link.link.type()
      reporter.update(`checked link ${link.link.seqno()}`)
      switch (type) {
        case 'sibkey':
          await this.playSibkey(link, sigId, keyring, keyFamily)
          break
        case 'subkey':
          this.playSubkey(link, sigId, keyFamily)
          break
        case 'pgp_update':
          this.playPgpUpdate(link, keyring, keyFamily)
          break
        case 'per_user_key':
          await this.playPerUserKey(link, sigId, keyring, keyFamily)
          break
        case 'eldest':
          throw new Error(`unexpected eldest in middle of subchain ${i}`)
      }
      await timeout(1)
      const revokes = link.link.revokes()
      keyFamily.revokeBatch(revokes)
      i++
    }

    reporter.success(`got key family: ${chalk.bold(keyFamily.summary())}`)
    const ret = new UserKeys(keyring, keyFamily)
    return ret
  }

  checkSubchainAgainstResetChain(chain: UserSigChain, subchain: ChainLinkBundle[]): ChainLinkBundle[] {
    const fullChain = chain.links
    const resetChain = chain.resets
    const empty: ChainLinkBundle[] = []
    // Empty chain, no reason for it be reset
    if (isEmpty(fullChain)) {
      return empty
    }

    if (isEmpty(subchain) && isEmpty(resetChain)) {
      throw new Error('need a reset if our subchain is nil')
    }

    if (isEmpty(subchain)) {
      return subchain
    }

    const first = new ChainLink(subchain[0].inner)
    const last = new ChainLink(subchain[subchain.length - 1].inner)

    if (isEmpty(resetChain) && first.seqno() != 1) {
      throw new Error("got a reset account, but didn't have a reset chain")
    }

    if (isEmpty(resetChain)) {
      return subchain
    }

    const lastReset = resetChain[resetChain.length - 1]
    const prevSeqno = lastReset.prev.public_seqno

    if (first.seqno() == prevSeqno + 1) {
      return subchain
    }

    // We were just reset on the server-side, so we throw away the last subchain
    if (last.seqno() == prevSeqno) {
      return empty
    }

    throw new Error("server's reset chain contradicts the cropped subchain")
  }

  async play(chain: UserSigChain, keyring: Keyring): Promise<UserKeys | null> {
    const subchain = this.cropToRightmostSubchain(chain)
    const subchainAfterResets = this.checkSubchainAgainstResetChain(chain, subchain)
    const ret = await this.playSubchain(chain.uid, subchainAfterResets, keyring, chain.eldest)
    return ret
  }
}
