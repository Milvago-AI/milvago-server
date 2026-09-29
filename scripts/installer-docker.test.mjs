import {test} from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync,mkdtempSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {spawnSync} from 'node:child_process';
const source=readFileSync('install-private.sh','utf8');
const begin=source.indexOf('inspect_docker_cli() {');
const end=source.indexOf('valid_public_origin() {',begin);
assert.ok(begin>0 && end>begin);
assert.ok(source.indexOf('\ninspect_docker_cli\n')<source.indexOf('\nensure_prerequisites\n'));
const planStart=source.indexOf('install_compose=0');
const planEnd=source.indexOf('if (( install_engine || install_compose )); then',planStart);
assert.ok(planEnd>planStart);
const bash=process.platform==='win32'?'C:/Program Files/Git/bin/bash.exe':'/usr/bin/bash';
function run(path,version=0,compose=0){
 const log=join(mkdtempSync(join(tmpdir(),'milvago-cli-test-')),'calls');
 const r=spawnSync(bash,['-c',`set -euo pipefail
fail(){ printf '%s' "$*" >&2; exit 1; }
command(){
  if [[ "$1" == -v && "$2" == docker ]]; then
    [[ -n "$TEST_DOCKER_PATH" ]] || return 1
    printf '%s' "$TEST_DOCKER_PATH"
  else builtin command "$@"; fi
}
docker(){
  printf '%s\\n' "$*" >> "$TEST_LOG"
  if [[ "$1" == --version ]]; then return "$TEST_VERSION_STATUS"; fi
  return "$TEST_COMPOSE_STATUS"
}
compose_supports_reset(){ return 0; }
${source.slice(begin,end)}
printf 'prerequisites\\n' >> "$TEST_LOG"
${source.slice(planStart,planEnd)}
printf 'engine=%s compose=%s' "$install_engine" "$install_compose"
`],{env:{...process.env,TEST_DOCKER_PATH:path,TEST_VERSION_STATUS:String(version),TEST_COMPOSE_STATUS:String(compose),TEST_LOG:log},encoding:'utf8'});
 let calls='';try{calls=readFileSync(log,'utf8');}catch{}
 return {...r,calls};
}
test('Windows interop shim fails before any prerequisite or Compose call',()=>{
 const r=run('/mnt/c/Program Files/Docker/docker',1,1);
 assert.notEqual(r.status,0);assert.equal(r.calls,'');
 assert.ok(r.stderr.includes('WSL integration'));assert.ok(r.stderr.includes('Resources'));
});
test('broken native CLI fails before prerequisite or Compose call',()=>{
 const r=run('/usr/bin/docker',1,1);assert.notEqual(r.status,0);
 assert.equal(r.calls.trim(),'--version');assert.ok(r.stderr.includes('present but does not run'));
});
test('missing CLI permits installing the engine and Compose',()=>{
 const r=run('');assert.equal(r.status,0,r.stderr);assert.equal(r.stdout,'engine=1 compose=1');
 assert.equal(r.calls.trim(),'prerequisites');
});
for(const path of ['/usr/bin/docker','/usr/local/bin/docker']){
 test('working Linux CLI is preserved: '+path,()=>{
  const r=run(path);assert.equal(r.status,0,r.stderr);assert.equal(r.stdout,'engine=0 compose=0');
 });
}
test('working CLI without Compose retains the Compose installation path',()=>{
 const r=run('/usr/bin/docker',0,1);assert.equal(r.status,0,r.stderr);assert.equal(r.stdout,'engine=0 compose=1');
});
