#!/usr/bin/env node
/**
 * Wolf #3 genuine Nodiom MCP stdio qualification on synthetic files only.
 * Must be invoked in a network-disabled container. No credentials or live services.
 * Usage: node nodiom-wolf3-mcp.mjs PINNED_MCP_REPO OUTPUT_DIR
 */
import {spawn} from 'node:child_process';
import {createHash} from 'node:crypto';
import {mkdtemp,mkdir,readFile,rm,writeFile} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join,resolve} from 'node:path';
import assert from 'node:assert/strict';

assert.equal(process.argv.length,4,'Usage: node nodiom-wolf3-mcp.mjs MCP_REPO OUT');
const mcpRepo=resolve(process.argv[2]);
const output=resolve(process.argv[3]);
await mkdir(output,{recursive:true});
const fixture=await mkdtemp(join(tmpdir(),'wolf3-mcp-fixture-'));
const sha=s=>createHash('sha256').update(s).digest('hex');
const success=r=>Boolean(!r.error && r.result && !r.result.isError);
const seed='# Wolf3 Synthetic\n\n## Tasks\n\n- [ ] seed\n\n'+('fixture padding line\n'.repeat(2048));
let nextId=0;
class Client {
  constructor(child){
    this.child=child;
    this.waiting=new Map();
    this.tail='';
    this.stderr='';
    child.stdout.setEncoding('utf8');
    child.stderr.setEncoding('utf8');
    child.stdout.on('data',chunk=>{
      this.tail+=chunk;
      while(this.tail.includes('\n')){
        const p=this.tail.indexOf('\n'),line=this.tail.slice(0,p);
        this.tail=this.tail.slice(p+1);
        if(!line.trim())continue;
        let message;
        try{message=JSON.parse(line);}catch{continue;}
        if(!Object.hasOwn(message,'id'))continue;
        const pending=this.waiting.get(message.id);
        if(pending){clearTimeout(pending.timer);this.waiting.delete(message.id);pending.resolve(message);}
      }
    });
    child.stderr.on('data',chunk=>this.stderr=(this.stderr+chunk).slice(-1024));
    child.on('error',e=>this.abort(e));
    child.on('exit',code=>this.abort(Error('Child exited: '+code+' '+this.stderr)));
  }
  abort(e){for(const p of this.waiting.values()){clearTimeout(p.timer);p.reject(e);}this.waiting.clear();}
  request(method,params={}){
    const id=++nextId;
    return new Promise((resolve,reject)=>{
      const timer=setTimeout(()=>{this.waiting.delete(id);reject(Error('Timeout '+method));},15000);
      this.waiting.set(id,{resolve,reject,timer});
      this.child.stdin.write(JSON.stringify({jsonrpc:'2.0',id,method,params})+'\n');
    });
  }
  notify(method){this.child.stdin.write(JSON.stringify({jsonrpc:'2.0',method})+'\n');}
  async initialize(){
    const r=await this.request('initialize',{protocolVersion:'2025-03-26',capabilities:{},clientInfo:{name:'wolf3-offline',version:'1.0'}});
    assert(!r.error,JSON.stringify(r.error));
    this.notify('notifications/initialized');
    return r.result;
  }
  stop(){this.child.stdin.end();this.child.kill('SIGTERM');}
}
const clients=[];
const count=8;
const report={
  schema:'wolftrap.nodiom.wolf3.mcp/v1',
  scope:'PINNED LOCAL STDIO; NETWORK-DISABLED; SYNTHETIC DOCUMENTS',
  clientCount:count,
  controls:{},
  rounds:[],
  verdict:'INCONCLUSIVE'
};
const call=(client,name,args)=>client.request('tools/call',{name,arguments:args});
try{
  for(let i=0;i<count;i++){
    const child=spawn(process.execPath,[join(mcpRepo,'dist','index.js')],{
      cwd:fixture,stdio:['pipe','pipe','pipe'],
      env:{HOME:fixture,PATH:process.env.PATH||'/usr/local/bin:/usr/bin:/bin',NODE_ENV:'production'}
    });
    clients.push(new Client(child));
  }
  const init=await Promise.all(clients.map(c=>c.initialize()));
  const inventory=await clients[0].request('tools/list');
  assert(!inventory.error && Array.isArray(inventory.result?.tools),'MCP tools/list failed');
  for(const expected of ['nodiom_tree','nodiom_read','nodiom_append','nodiom_write','nodiom_delete']){
    assert(inventory.result.tools.some(t=>t.name===expected),'Missing '+expected);
  }
  const list={schema:'wolftrap.nodiom.local-mcp-tools/v1',
    protocol:init[0].protocolVersion,serverInfo:init[0].serverInfo,tools:inventory.result.tools};
  const bytes=JSON.stringify(list,null,2)+'\n';
  await writeFile(join(output,'tools-list.json'),bytes);
  report.protocol=init[0].protocolVersion;
  report.serverInfo=init[0].serverInfo;
  report.toolNames=inventory.result.tools.map(t=>t.name);
  report.toolsListSha256=sha(bytes);

  // Positive control: sequential, genuine RPC writes all persist.
  const serialFile=join(fixture,'serialized.md');
  await writeFile(serialFile,seed);
  for(let i=0;i<count;i++){
    const reply=await call(clients[i],'nodiom_append',{
      file:serialFile,selector:'# Wolf3 Synthetic > ## Tasks',content:'- [ ] SERIAL-'+i
    });
    assert(success(reply),'Serialized MCP append failed: '+JSON.stringify(reply));
  }
  const serialized=await readFile(serialFile,'utf8');
  report.controls.serialPreservesAll=Array.from({length:count},(_,i)=>'SERIAL-'+i).every(t=>serialized.includes(t));
  assert(report.controls.serialPreservesAll,'Serialized control lost an update');

  // Characterization only; absolute local paths are documented functionality.
  const other=join(fixture,'outside-current-working-directory.md');
  await writeFile(other,'# Synthetic Canary\n\nCANARY-ONLY-NEVER-REAL-DATA\n');
  const read=await call(clients[0],'nodiom_read',{file:other,selector:'# Synthetic Canary'});
  report.controls.callerSelectedPathWorks=success(read)&&JSON.stringify(read.result).includes('CANARY-ONLY');
  assert(report.controls.callerSelectedPathWorks,'Caller-selected path control failed');

  // Eight independent MCP processes simultaneously append a unique marker.
  for(let round=0;round<16;round++){
    const file=join(fixture,'concurrent-'+round+'.md');
    await writeFile(file,seed);
    const markers=Array.from({length:count},(_,i)=>'WOLF3-ROUND-'+round+'-AGENT-'+i);
    const replies=await Promise.all(clients.map((c,i)=>call(c,'nodiom_append',{
      file,selector:'# Wolf3 Synthetic > ## Tasks',content:'- [ ] '+markers[i]
    })));
    const successes=replies.filter(success).length;
    const after=await readFile(file,'utf8');
    const retained=markers.filter(marker=>after.includes(marker)).length;
    report.rounds.push({round,reportedSuccess:successes,reportedError:count-successes,
      retained,missingCount:count-retained,seedPreserved:after.includes('- [ ] seed'),
      documentSha256:sha(after)});
    if(successes===count && retained<count){
      report.verdict='OBSERVED_LOST_UPDATE_IN_PINNED_LOCAL_MCP';
      break;
    }
  }
  if(report.verdict==='INCONCLUSIVE'){
    report.verdict=report.rounds.every(r=>r.reportedError===0)
      ? 'NOT_OBSERVED_IN_BOUNDED_ROUNDS':'MCP_TOOL_ERRORS_PREVENT_CONCLUSION';
  }
  report.limitations='Local, genuine pinned stdio implementation only. No Synexiom Cloud testing. Concurrency is probabilistic; a clean bounded run does not certify safety. Neither tool documentation nor runtime findings alone establish external exploitability.';
  console.log('Wolf #3 genuine local MCP verdict: '+report.verdict);
}catch(e){
  report.failure=String(e);
  throw e;
}finally{
  await writeFile(join(output,'mcp-runtime.json'),JSON.stringify(report,null,2)+'\n');
  clients.forEach(c=>c.stop());
  await rm(fixture,{recursive:true,force:true});
}
