import {UserSigChain, UserKeys, ChainLinkJSON, ResetChain} from './types'

export class Player {
  cropToRightmostSubchain(links: ChainLinkJSON[]): ChainLinkJSON[] {
    if (links.length === 0) {
      return [] as ChainLinkJSON[]
    }
    const lastLink = links[links.length - 1]
  }

  playSubchain(chain: ChainLinkJSON[]): UserKeys {
    return {} as UserKeys
  }

  checkSubchainAgainstResetChain(subchain: ChainLinkJSON[], resetChain: ResetChain) {
    return
  }

  play(chain: UserSigChain): UserKeys {
    const subchain = this.cropToRightmostSubchain(chain.links)
    this.checkSubchainAgainstResetChain(subchain, chain.resets)
    const ret = this.playSubchain(subchain)
    return ret
  }
}
