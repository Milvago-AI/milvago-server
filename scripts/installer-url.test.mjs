import {test} from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync,mkdtempSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {spawnSync} from 'node:child_process';
const source=readFileSync('install-private.sh','utf8');
const start=source.indexOf('valid_public_origin() {');
const end=source.indexOf('\numask 077',start);
// Checked inside a test case so a missing marker fails this file by name.
test('installer URL section markers exist',()=>{
 assert.ok(start>0 && end>start);
});
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


const helpersEnd=source.indexOf('\nselect_public_origin\n',start);
test('rerun helpers and final URL resolution remain before generated runtime writes',()=>{
 assert.ok(helpersEnd>start && helpersEnd<end);
 const lookup=source.indexOf('stored_origin=$(read_stored_public_origin "$database_id")');
 const resolve=source.indexOf('reuse_stored_public_origin "$stored_origin"',lookup);
 assert.ok(lookup>helpersEnd && resolve>lookup && resolve<source.indexOf('caddyfile="$root/.local/generated/Caddyfile.private"'));
 assert.ok(source.includes('database_id=$(resolve_database_container) || fail'));
 assert.ok(!source.includes('SELECT public_url FROM app_config WHERE singleton AND public_url_confirmed'));
});
function rerun({value,terminal=false,answer='',database='fixture-db',schema='configured',row='confirmed:https://milvago.example.test',ready=0,schemaStatus=0,rowStatus=0,startStatus=0}={}){
 const env={...process.env,URL_TEST_ANSWER:answer,URL_TEST_DATABASE:database,URL_TEST_SCHEMA:schema,URL_TEST_ROW:row,URL_TEST_READY:String(ready),URL_TEST_SCHEMA_STATUS:String(schemaStatus),URL_TEST_ROW_STATUS:String(rowStatus),URL_TEST_START_STATUS:String(startStatus)};
 delete env.MILVAGO_PUBLIC_URL;delete env.MILVAGO_HOST_IP;
 if(value!==undefined)env.MILVAGO_PUBLIC_URL=value;
 const definitions=source.slice(start,helpersEnd).replaceAll('/dev/tty',terminal?'/dev/null':'/milvago-no-terminal');
 return spawnSync(bash,['-c',`set -euo pipefail
fail(){ printf '%s\\n' "$*" >&2; exit 1; }
prerequisite_calls=0
ensure_prerequisites(){ prerequisite_calls=$((prerequisite_calls+1)); printf 'PREREQUISITES\\n' >&2; }
detect_host_ip(){ printf 'HOST_DETECTION\\n' >&2; printf '192.168.10.20'; }
read(){ public_origin=$URL_TEST_ANSWER; }
sleep(){ :; }
run_docker(){
 case "$*" in
  'start '*) return "$URL_TEST_START_STATUS" ;;
  *pg_isready*) return "$URL_TEST_READY" ;;
  *'FROM pg_catalog.pg_class'*) printf '%s' "$URL_TEST_SCHEMA"; return "$URL_TEST_SCHEMA_STATUS" ;;
  *'FROM public.app_config'*) printf '%s' "$URL_TEST_ROW"; return "$URL_TEST_ROW_STATUS" ;;
  *) fail 'Unexpected mocked Docker call' ;;
 esac
}
${definitions}
select_public_origin
select_host_binding
stored_origin=$(read_stored_public_origin "$URL_TEST_DATABASE") || fail 'Existing configuration read failed.'
reuse_stored_public_origin "$stored_origin"
printf 'RESULT=%s|%s|explicit=%s|prerequisites=%s\\n' "$public_origin" "$host_ip" "$public_origin_explicit" "$prerequisite_calls"
`],{env,encoding:'utf8',input:'unused piped script content'});
}
for(const options of [{},{terminal:true},{terminal:true,answer:''}]){
 test('implicit rerun keeps confirmed public origin '+JSON.stringify(options),()=>{
  const r=rerun(options);assert.equal(r.status,0,r.stderr);
  assert.ok(r.stdout.includes('RESULT=https://milvago.example.test|192.168.10.20|explicit=0|prerequisites=2'));
  assert.equal((r.stderr.match(/HOST_DETECTION/g)||[]).length,1);
 });
}
for(const options of [{value:'https://milvago.example.test/'},{terminal:true,answer:'https://milvago.example.test'}]){
 test('explicit matching rerun '+JSON.stringify(options),()=>{
  const r=rerun(options);assert.equal(r.status,0,r.stderr);
  assert.ok(r.stdout.includes('explicit=1|prerequisites=1'));
 });
}
for(const options of [{value:''},{value:'http://localhost:4020'},{value:'https://other.example.test'},{terminal:true,answer:'https://other.example.test'}]){
 test('explicit mismatch remains a refusal '+JSON.stringify(options),()=>{
  const r=rerun(options);assert.notEqual(r.status,0);assert.ok(r.stderr.includes('instance already uses'));
  assert.ok(!r.stdout.includes('RESULT='));
 });
}
for(const value of ['milvago.example.test','https://host:0','https://host:65536','https://host/path','https://host?query','https://host#fragment','https://user:password@host','https://host\ncommand','https://host/$(command)']){
 test('malformed explicit rerun stops before prerequisites '+JSON.stringify(value),()=>{
  const r=rerun({value});assert.notEqual(r.status,0);assert.ok(!r.stderr.includes('PREREQUISITES'));
  assert.ok(!r.stdout.includes('RESULT='));
 });
}
for(const options of [{schema:'empty'},{row:'unconfirmed'}]){
 test('known bootstrap retains local default '+JSON.stringify(options),()=>{
  const r=rerun(options);assert.equal(r.status,0,r.stderr);
  assert.ok(r.stdout.includes('RESULT=http://localhost:4020|127.0.0.1|explicit=0|prerequisites=1'));
  assert.ok(!r.stderr.includes('HOST_DETECTION'));
 });
}
test('stored loopback stays private without LAN detection',()=>{
 const r=rerun({row:'confirmed:http://127.0.0.1:4020'});assert.equal(r.status,0,r.stderr);
 assert.ok(r.stdout.includes('RESULT=http://127.0.0.1:4020|127.0.0.1'));assert.ok(!r.stderr.includes('HOST_DETECTION'));
});
for(const origin of ['HTTPS://milvago.example.test','HtTpS://milvago.example.test']){
 test('confirmed mixed-case HTTPS origin is preserved '+origin,()=>{
  const r=rerun({row:'confirmed:'+origin});assert.equal(r.status,0,r.stderr);
  assert.ok(r.stdout.includes('RESULT='+origin+'|192.168.10.20'));
 });
}
test('confirmed mixed-case HTTP loopback stays private',()=>{
 const r=rerun({row:'confirmed:HTTP://LOCALHOST:4020'});assert.equal(r.status,0,r.stderr);
 assert.ok(r.stdout.includes('RESULT=HTTP://LOCALHOST:4020|127.0.0.1'));
 assert.ok(!r.stderr.includes('HOST_DETECTION'));
});
for(const options of [{database:''},{ready:1},{startStatus:1},{schemaStatus:1},{rowStatus:1},{schema:'incomplete'},{schema:''},{schema:'unexpected'},{row:''},{row:'unconfirmed\nunconfirmed'},{row:'confirmed:'},{row:'confirmed:https://host/path'},{row:'confirmed:https://host\ncommand'}]){
 test('unreadable or malformed existing state cannot fall back to localhost '+JSON.stringify(options),()=>{
  const r=rerun(options);assert.notEqual(r.status,0);assert.ok(!r.stdout.includes('RESULT='));
  assert.ok(!r.stderr.includes('HOST_DETECTION'));
 });
}
function resolveDatabase({initial='fixture-db',after='restored-db',inspectStatus=0,createStatus=0,afterStatus=0}={}){
 const directory=mkdtempSync(join(tmpdir(),'milvago-database-lookup-'));
 const env={...process.env,LOOKUP_DIR:directory,LOOKUP_INITIAL:initial,LOOKUP_AFTER:after,LOOKUP_INSPECT_STATUS:String(inspectStatus),LOOKUP_CREATE_STATUS:String(createStatus),LOOKUP_AFTER_STATUS:String(afterStatus)};
 const result=spawnSync(bash,['-c',`set -euo pipefail
fail(){ printf '%s\\n' "$*" >&2; exit 1; }
run_docker(){
 case "$*" in
  'compose -f compose.yaml ps -a -q database')
   if [[ -f "$LOOKUP_DIR/inspected" ]]; then printf '%s' "$LOOKUP_AFTER"; return "$LOOKUP_AFTER_STATUS"; fi
   : > "$LOOKUP_DIR/inspected"
   printf '%s' "$LOOKUP_INITIAL"; return "$LOOKUP_INSPECT_STATUS"
   ;;
  'compose -f compose.yaml -f - create --no-recreate --no-build database')
   cat > "$LOOKUP_DIR/create-input"
   printf 'Docker progress must not enter the container ID\\n'
   return "$LOOKUP_CREATE_STATUS"
   ;;
  *) fail 'Unexpected database lookup call' ;;
 esac
}
${source.slice(start,helpersEnd)}
database=$(resolve_database_container) || fail 'Database lookup failed.'
printf 'RESULT=%s' "$database"
`],{env,encoding:'utf8'});
 let creation='';try{creation=readFileSync(join(directory,'create-input'),'utf8');}catch{}
 return {...result,creation};
}
test('existing database container is inspected without creation',()=>{
 const r=resolveDatabase();assert.equal(r.status,0,r.stderr);assert.equal(r.stdout,'RESULT=fixture-db');assert.equal(r.creation,'');
});
test('removed container is recreated against its configured volume before origin lookup',()=>{
 const r=resolveDatabase({initial:''});assert.equal(r.status,0,r.stderr);assert.equal(r.stdout,'RESULT=restored-db');
 assert.equal(r.creation,'services:\n  database:\n    ports: !reset []\n');
});
for(const options of [{inspectStatus:1},{initial:'',createStatus:1},{initial:'',afterStatus:1},{initial:'',after:''}]){
 test('failed or empty database container lookup stops rerun '+JSON.stringify(options),()=>{
  const r=resolveDatabase(options);assert.notEqual(r.status,0);assert.ok(!r.stdout.includes('RESULT='));
 });
}
test('existing database readiness waits for the final TCP server, not the init-time socket server',()=>{
 // The image entrypoint creates the milvago database on a socket-only temporary server.
 assert.match(source,/pg_isready -h 127\.0\.0\.1 -U postgres -d milvago/);
 assert.doesNotMatch(source,/pg_isready -U postgres >/);
});
