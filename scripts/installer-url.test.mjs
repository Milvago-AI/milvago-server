import {test} from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {spawnSync} from 'node:child_process';
const source=readFileSync('install-private.sh','utf8');
const start=source.indexOf('valid_public_origin() {');
const end=source.indexOf('\numask 077',start);
assert.ok(start>0 && end>start);
const bash=process.platform==='win32'?'C:/Program Files/Git/bin/bash.exe':'/usr/bin/bash';
function select({value,terminal=false,answer='',host}={}){
 const env={...process.env,URL_TEST_ANSWER:answer};
 delete env.MILVAGO_PUBLIC_URL;delete env.MILVAGO_HOST_IP;
 if(value!==undefined)env.MILVAGO_PUBLIC_URL=value;
 if(host!==undefined)env.MILVAGO_HOST_IP=host;
 const code=source.slice(start,end).replaceAll('/dev/tty',terminal?'/dev/null':'/milvago-no-terminal');
 return spawnSync(bash,['-c',`set -euo pipefail
fail(){ printf '%s\\n' "$*" >&2; exit 1; }
ensure_prerequisites(){ :; }
detect_host_ip(){ printf '192.168.10.20'; }
read(){ public_origin=$URL_TEST_ANSWER; }
${code}
printf 'RESULT=%s|%s\\n' "$public_origin" "$host_ip"
`],{env,encoding:'utf8',input:'unused piped script content'});
}
for(const options of [{},{value:''},{terminal:true},{value:'http://localhost:4020'},{value:'http://localhost:4020/',host:'192.168.10.20'}]){
 test('local default '+JSON.stringify(options),()=>{
  const result=select(options);assert.equal(result.status,0,result.stderr);
  assert.ok(result.stdout.includes('RESULT=http://localhost:4020|127.0.0.1'));
 });
}
test('explicit loopback address stays local',()=>assert.ok(select({value:'http://127.0.0.1:4020'}).stdout.includes('RESULT=http://127.0.0.1:4020|127.0.0.1')));
for(const options of [{value:'https://milvago.example.com'},{terminal:true,answer:'https://milvago.example.com'}]){
 test('public address '+JSON.stringify(options),()=>{
  const result=select(options);assert.equal(result.status,0,result.stderr);
  assert.ok(result.stdout.includes('RESULT=https://milvago.example.com|192.168.10.20'));
 });
}
test('invalid supplied URL is rejected instead of becoming localhost',()=>{
 const result=select({value:'milvago.example.com'});assert.notEqual(result.status,0);
 assert.ok(result.stderr.includes('HTTP or HTTPS'));
});
