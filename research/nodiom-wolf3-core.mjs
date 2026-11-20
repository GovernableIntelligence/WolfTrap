#!/usr/bin/env node
/** Genuine pinned Nodiom library, deterministic stale-snapshot / locking controls. */
import {createHash} from 'node:crypto';
import {mkdtemp,mkdir,readFile,rm,writeFile} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join,resolve} from 'node:path';
import {pathToFileURL} from 'node:url';
import assert from 'node:assert/strict';
assert(process.argv.length===4,'Usage: node nodiom-wolf3-core.mjs CORE_REPO EVIDENCE_DIR');
const coreRepo=resolve(process.argv[2]); const out=resolve(process.argv[3]);
const {Nodiom}=await import(pathToFileURL(join(coreRepo,'dist','index.js')).href);
await mkdir(out,{recursive:true});
const temp=await mkdtemp(join(tmpdir(),'wolf3-core-fixtures-'));
const base='# Wolf3 Synthetic\n\n## Tasks\n\n- [ ] seed\n';
const result={schema:'wolftrap.nodiom.wolf3.core/v1',exposure:'LOCAL-ONLY SYNTHETIC FILES',controls:{}};
try {
  const staleFile=join(temp,'stale.md');await writeFile(staleFile,base);
  const [first,second]=await Promise.all([Nodiom.fromFile(staleFile),Nodiom.fromFile(staleFile)]);
  first.append('# Wolf3 Synthetic > ## Tasks','- [ ] FIRST-WRITER');
  second.append('# Wolf3 Synthetic > ## Tasks','- [ ] SECOND-WRITER');
  await first.save();await second.save();
  const stale=await readFile(staleFile,'utf8');
  result.controls.staleSnapshot={firstRetained:stale.includes('FIRST-WRITER'),secondRetained:stale.includes('SECOND-WRITER'),sha256:createHash('sha256').update(stale).digest('hex')};
  assert.equal(result.controls.staleSnapshot.firstRetained,false,'Unexpected first writer retained in explicit stale-snapshot control');
  assert.equal(result.controls.staleSnapshot.secondRetained,true);

  const lockedFile=join(temp,'locked.md');await writeFile(lockedFile,base);
  const workers=8;
  await Promise.all(Array.from({length:workers},async (_,i)=>{
    const doc=await Nodiom.fromFile(lockedFile,{lock:true,lockTimeout:15000});
    try {doc.append('# Wolf3 Synthetic > ## Tasks','- [ ] LOCKED-'+i);await doc.save();}
    finally {await doc.unlock();}
  }));
  const locked=await readFile(lockedFile,'utf8');
  result.controls.advisoryLock={workers,retained:Array.from({length:workers},(_,i)=>i).filter(i=>locked.includes('LOCKED-'+i)).length,
    sha256:createHash('sha256').update(locked).digest('hex')};
  assert.equal(result.controls.advisoryLock.retained,workers,'Locking control lost a writer');
  result.verdict='PINNED_CORE_STALE_LOSS_AND_LOCKED_CONTROL_CONFIRMED';
  console.log('Wolf #3 genuine core verdict: '+result.verdict);
} catch(e) {result.verdict='INCONCLUSIVE';result.error=String(e);throw e;}
finally {await writeFile(join(out,'core-runtime.json'),JSON.stringify(result,null,2)+'\n');await rm(temp,{recursive:true,force:true});}
