import ora from 'ora'

export interface Step {
  start(s?: string): void
  update(s: string): void
  success(s: string): void
  fail(s: string): void
  step(): Step
}
export interface Reporter {
  step(s: string): Step
  error(e: Error): void
}

export class NullStep {
  constructor(s: string) {
    return
  }
  start(s?: string): void {
    return
  }
  update(s: string): void {
    return
  }
  success(s: string): void {
    return
  }
  fail(s: string): void {
    return
  }
  step(): Step {
    return new NullStep('null')
  }
}

export class NullReporter implements Reporter {
  step(s: string): Step {
    return new NullStep(s)
  }
  error(e: Error): void {
    return
  }
}

class InteractiveStep implements Step {
  prefix: string
  spinner: ora.Ora
  constructor(p: string) {
    this.prefix = p
    this.spinner = ora(p)
    return
  }

  fmt(s: string): string {
    return [this.prefix, s].join(': ')
  }
  start(s?: string): void {
    if (!s) {
      this.spinner.start()
      return
    }
    this.spinner.start(this.fmt(s))
    return
  }
  update(s: string): void {
    this.spinner.text = this.fmt(s)
    return
  }
  success(s: string): void {
    this.spinner.succeed(this.fmt(s))
    return
  }
  fail(s: string): void {
    this.spinner.fail(this.fmt(s))
    return
  }
  step(): Step {
    return new NullStep('null')
  }
}

export class InteractiveReporter implements Reporter {
  n: number
  last: InteractiveStep | null
  constructor() {
    this.n = 0
  }
  step(s: string): InteractiveStep {
    this.n++
    const ret = new InteractiveStep(`${this.n}. ${s}`)
    this.last = ret
    return ret
  }
  error(e: Error): void {
    if (this.last != null) {
      this.last.fail(e.toString())
    }
  }
}

export const newReporter = (r: Reporter | null): Reporter => {
  return r ? r : new NullReporter()
}
