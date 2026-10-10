import assert from 'node:assert/strict'
import {chmodSync,linkSync,mkdtempSync,rmSync,symlinkSync,writeFileSync} from 'node:fs'
import {tmpdir} from 'node:os'
import {join} from 'node:path'
import test from 'node:test'
import {ownerFile,readPrivateJson} from '../src/provision.mjs'

test('private state rejects readable permissions, shared inodes and symbolic links', t => {
 const root=mkdtempSync(join(tmpdir(),'crowsi-private-state-'))
 t.after(()=>rmSync(root,{recursive:true,force:true}))
 const state=join(root,'state.json')
 writeFileSync(state,'{"test":true}',{mode:0o600})
 assert.deepEqual(readPrivateJson(state),{test:true})
 for(const mode of [0o640,0o644,0o660]) {
  chmodSync(state,mode)
  assert.equal(ownerFile(state),false)
  assert.throws(()=>readPrivateJson(state),/owner-file-unsafe/u)
 }
 chmodSync(state,0o600)
 const shared=join(root,'shared.json')
 linkSync(state,shared)
 assert.equal(ownerFile(state),false)
 assert.throws(()=>readPrivateJson(state),/owner-file-unsafe/u)
 rmSync(shared)
 const alias=join(root,'alias.json')
 symlinkSync(state,alias)
 assert.equal(ownerFile(alias),false)
 assert.throws(()=>readPrivateJson(alias))
 assert.deepEqual(readPrivateJson(state),{test:true})
})
