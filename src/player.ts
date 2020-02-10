import {UserSigChain, UserKeys, ChainLinkJSON, ResetChain, Kid, Uid, ChainLinkBundle} from './types'

class ChainLink {
  json: ChainLinkJSON
  constructor(j: ChainLinkJSON) {
    this.json = j
  }

  eldestKid = (): Kid | null => this.json.body.key.eldest_kid || this.json.body.key.kid
  uid = (): Uid => this.json.body.key.uid
  seqno = (): number => this.json.seqno
  isEldest = (): boolean => this.json.body.type == 'eldest'
  sigVersion = (): number => this.json.body.version
}

const hardcodedResets: {[key: string]: number} = {
  '2d5c41137d7d9108dbdaa2160ba7e200': 11,
  f1c263462dd526695c458af924977719: 8,
  '8dbf0f1617e285befa93d3da54b68419': 8,
  '372c1cbd72e4f851a74d232478a72319': 2,
  '12e124d5d1ff6179f3aab88100b93d19': 5,
  a07089770463db10994c8727177eef19: 12,
}

export class Player {
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

  playSubchain(chain: ChainLinkBundle[]): UserKeys {
    return {} as UserKeys
  }

  checkSubchainAgainstResetChain(chain: UserSigChain, subchain: ChainLinkBundle[]): ChainLinkBundle[] {
    const isEmpty = (c: Array<any>): boolean => !c || c.length == 0
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

  play(chain: UserSigChain): UserKeys {
    const subchain = this.cropToRightmostSubchain(chain)
    const subchainAfterResets = this.checkSubchainAgainstResetChain(chain, subchain)
    const ret = this.playSubchain(subchainAfterResets)
    return ret
  }
}
