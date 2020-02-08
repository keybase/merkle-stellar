import yargs from 'yargs'
import {Checker} from './check'
import {UserSigChain} from './types'
import fs from 'fs'

const parseArgv = () =>
  yargs
    .usage('Usage: $0 <uid|username> [options]')
    .demandCommand(1)
    .options({
      file: {type: 'string', alias: 'f', describe: 'output full JSON to file'},
    }).argv

const output = async (res: UserSigChain, fileName: string): Promise<void> => {
  if (!!fileName || process.stdout.isTTY) {
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

export const main = async () => {
  const argv = parseArgv()
  const chk = new Checker()
  if (process.stdout.isTTY) {
    chk.interactiveReporting()
  }
  const res = await chk.check(argv._[0])
  if (!res) {
    process.exit(2)
  }
  output(res, argv.file)
}
