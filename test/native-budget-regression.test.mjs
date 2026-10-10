import assert from 'node:assert/strict'
import {existsSync,mkdtempSync,rmSync,writeFileSync} from 'node:fs'
import {tmpdir} from 'node:os'
import {join} from 'node:path'
import test from 'node:test'
import {runNativeJson} from '../src/crowsi-native-process.mjs'

test('an oversized native response fails closed and reclaims descendant processes', async t => {
 const root=mkdtempSync(join(tmpdir(),'crowsi-native-budget-'))
 t.after(()=>rmSync(root,{recursive:true,force:true}))
 const marker=join(root,'survived')
 const descendant=join(root,'descendant.mjs')
 const provider=join(root,'provider.mjs')
 writeFileSync(descendant,`import fs from 'node:fs';process.send('ready');setTimeout(()=>fs.writeFileSync(${JSON.stringify(marker)},'unexpected'),500);`)
 writeFileSync(provider,`import {fork} from 'node:child_process';const child=fork(${JSON.stringify(descendant)},[],{stdio:['ignore','ignore','ignore','ipc']});child.once('message',()=>process.stdout.write('x'.repeat(2097152)));`)
 await assert.rejects(runNativeJson(process.execPath,[provider]),/crowsi-browser-security-/u)
 await new Promise(resolve=>setTimeout(resolve,800))
 assert.equal(existsSync(marker),false)
})

test('one-shot native providers cannot leave background descendants after success', async t => {
 const root=mkdtempSync(join(tmpdir(),'crowsi-native-close-'))
 t.after(()=>rmSync(root,{recursive:true,force:true}))
 const marker=join(root,'survived')
 const descendant=join(root,'descendant.mjs')
 const provider=join(root,'provider.mjs')
 writeFileSync(descendant,`import fs from 'node:fs';process.send('ready');setTimeout(()=>fs.writeFileSync(${JSON.stringify(marker)},'unexpected'),500);`)
 writeFileSync(provider,`import {fork} from 'node:child_process';const child=fork(${JSON.stringify(descendant)},[],{stdio:['ignore','ignore','ignore','ipc']});child.once('message',()=>{process.stdout.write('{"test":true}',()=>process.exit(0));});`)
 assert.deepEqual(await runNativeJson(process.execPath,[provider]),{test:true})
 await new Promise(resolve=>setTimeout(resolve,800))
 assert.equal(existsSync(marker),false)
})
