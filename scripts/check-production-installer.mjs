import assert from 'node:assert/strict';
import {cpSync,readFileSync,writeFileSync,mkdirSync,mkdtempSync,chmodSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {execFileSync} from 'node:child_process';
import {randomBytes} from 'node:crypto';
import {pathToFileURL} from 'node:url';
const template=readFileSync('install-private.sh','utf8');
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
const start=template.indexOf('override="$root/.local/generated/compose.private.yaml"');
const end=template.indexOf('\nEOF\n',start)+5;assert.ok(start>0&&end>start);
execFileSync('/usr/bin/bash',['-c','root="$PWD"\npublic_origin=https://console.example.test\nhost_ip=127.0.0.1\nIMAGE=unused-test-image\nUPDATE_PUBLIC_KEY=unused-test-key\nCADDY_IMAGE=unused-test-image\n'+template.slice(start,end)],{cwd:root,stdio:'pipe'});
writeFileSync(join(root,'test.yaml'),'services:\n  database:\n    ports: !override []\n  gateway:\n    ports: !override []\n');
const compose=['compose','-p',project,'-f',join(root,'compose.yaml'),'-f',join(root,'.local/generated/compose.private.yaml'),'-f',join(root,'test.yaml')];
const docker=args=>execFileSync('/usr/bin/docker',args,{cwd:root,encoding:'utf8',stdio:['ignore','pipe','pipe'],maxBuffer:4*1024*1024});
const nodeImage=template.match(/NODE_IMAGE='([^']+)'/)[1];
const section=template.slice(template.indexOf("printf 'Configuring Keycloak redirects"));
const codeStart=section.indexOf("node -e '\n")+"node -e '\n".length;
const configure=section.slice(codeStart,section.indexOf("\n' || fail",codeStart));assert.ok(configure.includes('factorySMTP'));
const runNode=(container,code)=>docker(['run','--rm','--network','container:'+container,'-v',root+':/work',nodeImage,'node','-e',code]);
try{
 const config=JSON.parse(docker([...compose,'--profile','development-mail','config','--format','json']));
 assert.deepEqual(config.services.identity.command,['start','--import-realm']);assert.equal(config.services.identity.environment.KC_HTTP_ENABLED,'true');
 assert.deepEqual(config.services.mail.profiles,['development-mail']);assert.equal(config.services.mail.user,'65532:65532');assert.ok(config.services.mail.cap_drop.includes('ALL'));
 assert.ok(!docker([...compose,'config','--services']).split('\n').includes('mail'));
 docker([...compose,'up','-d','database','identity']);
 const identity=docker([...compose,'ps','-q','identity']).trim();assert.ok(identity);
 const configureRun=()=>docker(['run','--rm','--network','container:'+identity,'-v',join(root,'.env')+':/run/milvago.env:ro','-e','MILVAGO_APP_URL=https://console.example.test',nodeImage,'node','-e',configure]);
 assert.ok(configureRun().includes('SMTP is not configured'));assert.ok(configureRun().includes('SMTP is not configured'));
 const real={host:'smtp.example.test',port:'587',from:'sender@example.test',auth:'false',starttls:'true'};
 cpSync('scripts/check-production-identity.mjs',join(root,'check-production-identity.mjs'));
 const identityFixture=(...args)=>docker(['run','--rm','--network','container:'+identity,'-v',root+':/work',nodeImage,'node','/work/check-production-identity.mjs',...args]);
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
