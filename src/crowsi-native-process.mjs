import { spawn } from 'node:child_process'

const maximumOutput = 1_048_576

export async function runNativeJson(executable, arguments_, input) {
  const result = await run(executable, arguments_, input)
  if (result.code !== 0 || result.timedOut) invalid(reason(result.output))
  try { return JSON.parse(result.output.toString('utf8')) }
  catch { invalid('response-invalid') }
}

function run(executable, arguments_, input) {
  return new Promise((resolve, reject) => {
    const child = spawn(executable, arguments_, options('pipe'))
    const chunks = []; let size = 0; let timedOut = false
    const collect = value => {
      size += value.length
      if (size > maximumOutput) child.kill('SIGKILL'); else chunks.push(value)
    }
    child.stdout.on('data', collect); child.stderr.on('data', collect)
    child.once('error', reject)
    const timer = setTimeout(() => { timedOut = true; child.kill('SIGKILL') }, 30_000)
    child.once('close', code => {
      clearTimeout(timer); resolve({ code: code ?? 1, timedOut,
        output: Buffer.concat(chunks) })
    })
    child.stdin.on('error', () => { /* early native exit is reported by close */ })
    child.stdin.end(input)
  })
}
function options(stdin) { return { shell: false, stdio: [stdin, 'pipe', 'pipe'], env: {
  PATH: '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin', LANG: 'C.UTF-8' } } }
function reason(value) { return nativeReason(value) || 'operation-failed' }
function nativeReason(value) { return value.toString('utf8')
  .match(/(?:crowsi-[a-z-]+: )?([a-z][a-z0-9-]+)$/mu)?.[1] }
function invalid(code) { throw new Error(`crowsi-browser-security-${code}`) }
