import yargs from 'yargs'
import {Runner} from './run'

const parseArgv = () =>
  yargs
    .usage('Usage: $0 <uid|username> [options]')
    .demandCommand(1)
    .options({
      file: {type: 'string', alias: 'f', describe: 'output full JSON to file'},
      tree: {type: 'boolean', alias: 't', describe: "check tree, but don't play chain"},
      quiet: {type: 'boolean', alias: 'q', describe: 'no fancy output'},
    }).argv

export const main = async () => {
  const argv = parseArgv()
  const runner = new Runner(argv, process.stdout.isTTY, argv._[0])
  const res = await runner.run()
  const rc = res ? 0 : 2
  process.exit(rc)
}
