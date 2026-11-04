import assert from 'node:assert/strict';
import {cpSync,readFileSync,writeFileSync,mkdirSync,mkdtempSync,chmodSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {execFileSync} from 'node:child_process';
import {randomBytes} from 'node:crypto';
import {pathToFileURL} from 'node:url';
const template=readFileSync('install-private.sh','utf8');
const origin=process.argv.includes('--localhost')?'http://localhost:4020':'https://console.example.test';
const begin=template.indexOf('  const factorySMTP = ');
const endMigration=template.indexOf('  realm.attributes =',begin);
assert.ok(begin>=0 && endMigration>begin);
// Import the migration from the installer under test as an isolated source module.
const fixture=join(mkdtempSync(join(tmpdir(),'milvago-smtp-test-')),'migration.mjs');
writeFileSync(fixture,'export function migrate(realm) {\n'+template.slice(begin,endMigration)+'\nreturn realm.smtpServer;\n}');
const {migrate}=await import(pathToFileURL(fixture).href);
const factory={host:'mail',port:'1025',from:'no-reply@milvago.test',fromDisplayName:'Milvago',auth:'false',ssl:'false',starttls:'false'};
assert.deepEqual(migrate({smtpServer:{...factory}}),{});
assert.deepEqual(migrate({smtpServer:{...factory,password:''}}),{});
assert.deepEqual(migrate({smtpServer:{}}),{});
for(const custom of [{...factory,host:'smtp.example.test'},{...factory,from:'sender@example.test'},{...factory,auth:'true'},{...factory,password:'test-placeholder'},{...factory,replyTo:'reply@example.test'}])assert.deepEqual(migrate({smtpServer:{...custom}}),custom);
assert.ok(template.includes('up -d --no-build database identity application gateway'));
assert.ok(template.includes('stop mail'));
if(process.argv.includes('--unit')){console.log('Factory SMTP removal and custom SMTP preservation passed.');process.exit(0);}
// Run only disposable services; never print their generated credentials.
const root=mkdtempSync(join(tmpdir(),'milvago-installer-'));
const project='milvago-installer-'+randomBytes(6).toString('hex');
mkdirSync(join(root,'scripts'));mkdirSync(join(root,'deploy'));
for(const name of ['local-init.mjs','identity-flows.mjs'])cpSync('scripts/'+name,join(root,'scripts',name));
cpSync('compose.yaml',join(root,'compose.yaml'));
cpSync('deploy/postgres-init.sh',join(root,'deploy/postgres-init.sh'));
cpSync('deploy/theme',join(root,'deploy/theme'),{recursive:true});
execFileSync(process.execPath,[join(root,'scripts/local-init.mjs')],{stdio:'pipe'});
chmodSync(join(root,'.local/generated/realm.json'),0o644);
// A rerun must keep existing secrets, custom environment entries and realm bytes.
const preservedNames=['compose.yaml','.env','.local/generated/realm.json'];
writeFileSync(join(root,'.env'),readFileSync(join(root,'.env'),'utf8')+'INSTALLER_PRESERVE_SENTINEL=operator-value\n');
const preserved=new Map(preservedNames.map(name=>[name,readFileSync(join(root,name))]));
execFileSync(process.execPath,[join(root,'scripts/local-init.mjs')],{stdio:'pipe'});
for(const [name,content] of preserved)assert.ok(readFileSync(join(root,name)).equals(content),'Existing installer configuration changed: '+name);
const start=template.indexOf('override="$root/.local/generated/compose.private.yaml"');
const end=template.indexOf('\nEOF\n',start)+5;assert.ok(start>0&&end>start);
const imageA='ghcr.io/milvago-ai/milvago-server:1.0.0@sha256:'+'a'.repeat(64);
const imageB='ghcr.io/milvago-ai/milvago-server:1.1.0@sha256:'+'b'.repeat(64);
// Digests are synthetic render inputs; this fixture does not verify/pull these images.
const renderOverride=image=>execFileSync('/usr/bin/bash',['-c','root="$PWD"\npublic_origin='+origin+'\nhost_ip=127.0.0.1\nIMAGE=$TEST_INSTALLER_IMAGE\nUPDATE_PUBLIC_KEY=unused-test-key\nCADDY_IMAGE=unused-test-image\n'+template.slice(start,end)],{cwd:root,env:{...process.env,TEST_INSTALLER_IMAGE:image},stdio:'pipe'});
renderOverride(imageA);
writeFileSync(join(root,'test.yaml'),'services:\n  database:\n    ports: !override []\n  gateway:\n    ports: !override []\n');
const compose=['compose','-p',project,'-f',join(root,'compose.yaml'),'-f',join(root,'.local/generated/compose.private.yaml'),'-f',join(root,'test.yaml')];
const docker=args=>execFileSync('/usr/bin/docker',args,{cwd:root,encoding:'utf8',stdio:['ignore','pipe','pipe'],maxBuffer:4*1024*1024});
const nodeImage=template.match(/NODE_IMAGE='([^']+)'/)[1];
const section=template.slice(template.indexOf("printf 'Configuring Keycloak redirects"));
const codeStart=section.indexOf("node -e '\n")+"node -e '\n".length;
const configure=section.slice(codeStart,section.indexOf("\n' || fail",codeStart));assert.ok(configure.includes('factorySMTP'));
const runNode=(container,code)=>docker(['run','--rm','--network','container:'+container,'-v',root+':/work',nodeImage,'node','-e',code]);
try{
 const published=JSON.parse(docker([...compose.slice(0,-2),'--profile','development-mail','config','--format','json']));
 assert.equal(published.services.gateway.ports[0].host_ip,'127.0.0.1');
 assert.equal(String(published.services.gateway.ports[0].published),'4020');
 const firstConfig=JSON.parse(docker([...compose,'--profile','development-mail','config','--format','json']));
 assert.equal(firstConfig.services.application.image,imageA);
 renderOverride(imageB);
 const config=JSON.parse(docker([...compose,'--profile','development-mail','config','--format','json']));
 assert.equal(config.services.application.image,imageB);
 assert.equal(config.services.database.image,firstConfig.services.database.image);
 assert.deepEqual(config.services.database.volumes,firstConfig.services.database.volumes);
 for(const [name,content] of preserved)assert.ok(readFileSync(join(root,name)).equals(content),'Existing configuration changed during image update: '+name);
 const updatedOverride=readFileSync(join(root,'.local/generated/compose.private.yaml'));
 renderOverride(imageB);
 assert.ok(readFileSync(join(root,'.local/generated/compose.private.yaml')).equals(updatedOverride),'Repeated image update changed generated configuration');
 for(const [name,content] of preserved)assert.ok(readFileSync(join(root,name)).equals(content),'Repeated image update changed existing configuration: '+name);
 assert.equal(config.services.application.environment.APP_URL,origin);
 let runtimePool;
 try{runtimePool=new URL(config.services.application.environment.DATABASE_URL).searchParams.getAll('pool_max_conns');}
 catch{assert.fail('Managed runtime database URL is invalid.');}
 assert.deepEqual(runtimePool,['12']);
 assert.equal(config.services.identity.environment.KC_HOSTNAME,origin);
 assert.deepEqual(config.services.identity.command,['start','--import-realm']);assert.equal(config.services.identity.environment.KC_HTTP_ENABLED,'true');
 assert.deepEqual(config.services.mail.profiles,['development-mail']);assert.equal(config.services.mail.user,'65532:65532');assert.ok(config.services.mail.cap_drop.includes('ALL'));
 assert.ok(!docker([...compose,'config','--services']).split('\n').includes('mail'));
 docker([...compose,'up','-d','database','identity']);
 // Exercise the actual read-only installer helper against this owned PG fixture.
 let database=docker([...compose,'ps','-q','database']).trim();assert.ok(database);
 const helpersStart=template.indexOf('valid_public_origin() {');
 const helpersEnd=template.indexOf('\nselect_public_origin\n',helpersStart);
 assert.ok(helpersStart>0&&helpersEnd>helpersStart);
 const readExistingOrigin=()=>execFileSync('/usr/bin/bash',['-c',`set -euo pipefail
fail(){ printf '%s\\n' "$*" >&2; exit 1; }
run_docker(){ /usr/bin/docker "$@"; }
${template.slice(helpersStart,helpersEnd)}
read_stored_public_origin "$TEST_EXISTING_DATABASE"
`],{cwd:root,env:{...process.env,TEST_EXISTING_DATABASE:database},encoding:'utf8',stdio:['ignore','pipe','pipe']});
 const resolveExistingDatabase=()=>execFileSync('/usr/bin/bash',['-c',`set -euo pipefail
fail(){ printf '%s\\n' "$*" >&2; exit 1; }
run_docker(){
 if [[ "$1" == compose ]]; then shift; /usr/bin/docker compose -p "$TEST_INSTALLER_PROJECT" "$@";
 else /usr/bin/docker "$@"; fi
}
${template.slice(helpersStart,helpersEnd)}
resolve_database_container
`],{cwd:root,env:{...process.env,TEST_INSTALLER_PROJECT:project},encoding:'utf8',stdio:['ignore','pipe','pipe']}).trim();
 const fixtureSQL=sql=>docker(['exec',database,'psql','-X','-v','ON_ERROR_STOP=1','-U','postgres','-d','milvago','-At','-c',sql]);
 assert.equal(readExistingOrigin(),'');
 fixtureSQL('CREATE TABLE public.installer_partial(id integer)');
 assert.throws(()=>readExistingOrigin());
 fixtureSQL('DROP TABLE public.installer_partial; CREATE TABLE public.app_config(singleton boolean PRIMARY KEY DEFAULT true CHECK(singleton),public_url text NOT NULL,public_url_confirmed boolean NOT NULL)');
 assert.throws(()=>readExistingOrigin());
 fixtureSQL("INSERT INTO public.app_config VALUES(true,'',false)");
 assert.equal(readExistingOrigin(),'');
 fixtureSQL("UPDATE public.app_config SET public_url='"+origin+"',public_url_confirmed=true");
 assert.equal(readExistingOrigin(),origin);
 // `compose down` removes containers but keeps named data volumes. Reuse those
 // bytes and inspect the confirmed origin before generating a runtime override.
 const volumeName=id=>JSON.parse(docker(['inspect','--format','{{json .Mounts}}',id])).find(mount=>mount.Destination==='/var/lib/postgresql').Name;
 const preservedVolume=volumeName(database);assert.ok(preservedVolume);
 const previousDatabase=database;
 docker([...compose,'stop','database']);docker(['rm',database]);
 database=resolveExistingDatabase();assert.ok(database && database!==previousDatabase);
 assert.equal(volumeName(database),preservedVolume);
 const bindings=JSON.parse(docker(['inspect','--format','{{json .HostConfig.PortBindings}}',database]));
 assert.ok(bindings===null || Object.keys(bindings).length===0,'Inspection must not publish database ports');
 assert.equal(readExistingOrigin(),origin);
 for(const [name,content] of preserved)assert.ok(readFileSync(join(root,name)).equals(content),'Database container recovery changed configuration: '+name);
 fixtureSQL("UPDATE public.app_config SET public_url='https://console.example.test/path'");
 assert.throws(()=>readExistingOrigin());
 fixtureSQL('ALTER TABLE public.app_config RENAME COLUMN public_url TO broken_public_url');
 assert.throws(()=>readExistingOrigin());
 fixtureSQL('DROP TABLE public.app_config');
 const identity=docker([...compose,'ps','-q','identity']).trim();assert.ok(identity);
 const configureRun=()=>docker(['run','--rm','--network','container:'+identity,'-v',join(root,'.env')+':/run/milvago.env:ro','-e','MILVAGO_APP_URL='+origin,nodeImage,'node','-e',configure]);
 assert.ok(configureRun().includes('SMTP is not configured'));assert.ok(configureRun().includes('SMTP is not configured'));
 const real={host:'smtp.example.test',port:'587',from:'sender@example.test',auth:'false',starttls:'true'};
 cpSync('scripts/check-production-identity.mjs',join(root,'check-production-identity.mjs'));
 const identityFixture=(...args)=>docker(['run','--rm','--network','container:'+identity,'-v',root+':/work',nodeImage,'node','/work/check-production-identity.mjs',...args]);
 identityFixture('discovery',origin);
 identityFixture('set',JSON.stringify(real));
 assert.ok(!configureRun().includes('SMTP is not configured'));
 identityFixture('verify',JSON.stringify(real));
 const logs=docker([...compose,'logs','identity']);assert.ok(!logs.includes('Running the server in development mode'));assert.ok(logs.includes('Profile prod activated'));
 docker([...compose,'--profile','development-mail','up','-d','mail']);
 const mail=docker([...compose,'ps','-q','mail']).trim();assert.ok(mail);
 runNode(mail,"(async()=>{for(let i=0;i<30;i++){try{if((await fetch('http://127.0.0.1:8025/')).ok)return;}catch{}await new Promise(r=>setTimeout(r,1000));}throw Error('Mailpit not ready');})().catch(e=>{console.error(e.message);process.exit(1)});");
 docker([...compose,'stop','mail']);assert.equal(JSON.parse(docker(['inspect',mail]))[0].State.Running,false);
 console.log('Production Keycloak started; legacy SMTP removed idempotently; real SMTP preserved; default services exclude Mailpit; non-root Mailpit started and stopped.');
}finally{
 // Only this random disposable project owns these volumes.
 docker([...compose,'--profile','development-mail','down','-v','--remove-orphans']);
}
