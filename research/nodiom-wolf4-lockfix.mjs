#!/usr/bin/env node
/**
 * Wolf #4: ephemeral Nodiom MCP locking-remediation regression.
 * Operates only on the disposable pinned source clone, not on the vendor repo.
 * patch SOURCE_TS EVIDENCE_JSON
 * verify MCP_RUNTIME_JSON EVIDENCE_JSON
 */
import {readFile,writeFile,mkdir} from 'node:fs/promises';
import {createHash} from 'node:crypto';
import {dirname,resolve} from 'node:path';
import assert from 'node:assert/strict';

assert.equal(process.argv.length,5,'Expected MODE SOURCE_OR_RUNTIME_JSON EVIDENCE_JSON');
const [, ,mode,inputPath,evidencePath]=process.argv;
const input=resolve(inputPath),evidence=resolve(evidencePath);
const sha=txt=>createHash('sha256').update(txt).digest('hex');
let report={schema:'wolftrap.nodiom.wolf4.lockfix/v1',
  scope:'EPHEMERAL LOCAL SOURCE PATCH ONLY; NO VENDOR CHANGES',
  stage:mode,verdict:'INCONCLUSIVE'};
try{
  if(mode==='patch'){
    let source=await readFile(input,'utf8');
    const originalSha256=sha(source);
    const changed=[];
    for(const [operation,args] of [['write','selector, content'],['append','selector, content'],['delete','selector']]){
      const expected=['const doc = await Nodiom.fromFile(file);','      doc.'+operation+'('+args+');','      await doc.save();'].join('\n');
      const count=source.split(expected).length-1;
      assert.equal(count,1,'Expected exact single mutable handler for '+operation+'; actual '+count);
      const replacement=[
        'const doc = await Nodiom.fromFile(file, { lock: true, lockTimeout: 15000 });',
        '      try {','        doc.'+operation+'('+args+');',
        '        await doc.save();','      } finally {',
        '        await doc.unlock();','      }'
      ].join('\n');
      source=source.replace(expected,replacement);
      changed.push(operation);
    }
    assert.equal((source.match(/Nodiom\.fromFile\(file, \{ lock: true, lockTimeout: 15000 \}\)/g)||[]).length,3);
    assert.equal((source.match(/Nodiom\.fromFile\(file\)/g)||[]).length,4,'Read-only handlers must remain unchanged');
    await writeFile(input,source);
    report={...report,operations:changed,sourceOriginalSha256:originalSha256,
      sourcePatchedSha256:sha(source),verdict:'EPHEMERAL_PATCH_APPLIED'};
  }else if(mode==='verify'){
    const raw=await readFile(input,'utf8');
    const fixture=JSON.parse(raw);
    assert.equal(fixture.schema,'wolftrap.nodiom.wolf3.mcp/v1');
    assert.equal(fixture.clientCount,8);
    assert.equal(fixture.controls.serialPreservesAll,true);
    assert.equal(fixture.controls.callerSelectedPathWorks,true);
    assert.equal(fixture.rounds.length,16,'Require all sixteen concurrency rounds');
    const failing=fixture.rounds.filter(r=>r.reportedSuccess!==8||r.retained!==8||r.missingCount!==0||!r.seedPreserved);
    report={...report,rounds:fixture.rounds.length,clients:fixture.clientCount,
      totalSuccessfulToolCalls:fixture.rounds.reduce((n,r)=>n+r.reportedSuccess,0),
      allMarkersPreserved:failing.length===0,
      successfulSequentialControl:fixture.controls.serialPreservesAll,
      failedRounds:failing.map(r=>r.round),
      sourceRunSha256:sha(raw),
      verdict:failing.length===0?'PINNED_LOCAL_PATCH_REGRESSION_PASS':'PINNED_LOCAL_PATCH_REGRESSION_FAIL'};
    assert.equal(failing.length,0,'Patched local MCP lost updates or reported tool errors');
  }else{
    throw new Error('Unknown mode');
  }
}catch(e){report={...report,verdict:'INCONCLUSIVE_OR_FAILED',error:String(e)};throw e;}
finally{
  await mkdir(dirname(evidence),{recursive:true});
  await writeFile(evidence,JSON.stringify(report,null,2)+'\n');
  console.log('Wolf #4 '+mode+' verdict: '+report.verdict);
}
