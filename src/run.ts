import {TreeWalker} from './tree'
import {Player} from './player'
import {InteractiveReporter, NullReporter} from './reporter'
import {Reporter} from './reporter'
import fs from 'fs'
import {UserSigChain} from './types'
import {KeyRing, UserKeys} from './keys'

const output = async (res: any, fileName: string): Promise<void> => {
  if (!fileName && process.stdout.isTTY) {
    return
  }
  const out = JSON.stringify(res)
  if (fileName) {
    await fs.promises.writeFile(fileName, out, {encoding: 'utf8', mode: '0644'})
    return
  }

  return new Promise((resolve, reject) => {
    process.stdout.write(out, err => {
      if (err) {
        reject(err)
      } else {
        resolve()
      }
    })
  })
}

export type Opts = {
  file: string
  tree: boolean
  quiet: boolean
}

export class Runner {
  opts: Opts
  username: string
  isTTY: boolean

  constructor(opts: Opts, isTTY: boolean, username: string) {
    this.opts = opts
    this.username = username
    this.isTTY = isTTY
  }

  async run(): Promise<boolean> {
    const reporter = this.isTTY && !this.opts.quiet ? new InteractiveReporter() : new NullReporter()
    try {
      const ret = await this.runWithReporter(reporter)
      await output(ret, this.opts.file)
      return true
    } catch (e) {
      reporter.error(e)
      return false
    }
  }

  async runWithReporter(r: Reporter): Promise<UserSigChain | UserKeys> {
    const treeWalker = new TreeWalker(r)
    const userSigChain = await treeWalker.walkUidOrUsername(this.username)
    if (this.opts.tree) {
      return userSigChain
    }
    const keyring = new KeyRing(userSigChain.uid, r)
    await keyring.fetch()
    const player = new Player(r)
    const userKeys = await player.play(userSigChain, keyring)
    return userKeys
  }
}
