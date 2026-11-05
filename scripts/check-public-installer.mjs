import {createHash,randomBytes} from 'node:crypto';
import {existsSync,mkdirSync,mkdtempSync,readFileSync,realpathSync,rmSync,writeFileSync} from 'node:fs';
import {spawnSync} from 'node:child_process';
import {isAbsolute,join,relative,resolve,sep} from 'node:path';
import {pathToFileURL} from 'node:url';

const official='https://github.com/Milvago-AI/milvago-server/releases/download/';
const oldInstallerSHA='1b65b015da35adeb14f11726964c4ee86c9f3bc51ad12baafee057bbd3bdb315';
const digest=bytes=>createHash('sha256').update(bytes).digest('hex');
const requireValue=(condition,code)=>{if(!condition)throw Error(code);};

export function qualificationVersion(value){
 requireValue(value==='1.1.1','unsupported_qualification_version');
 return value;
}

export function verifyPublicRelease(version,installer,metadata,sums){
 requireValue(version==='1.1.1'||version==='1.0.5','unsupported_asset_version');
 const lines=sums.toString('utf8').trimEnd().split('\n');
 requireValue(lines.length===2,'invalid_checksum_list');
 const listed=new Map();
 for(const line of lines){
  const match=/^([a-f0-9]{64})  (install-private\.sh|release\.json)$/.exec(line);
  requireValue(match&&!listed.has(match[2]),'invalid_checksum_list');
  listed.set(match[2],match[1]);
 }
 requireValue(listed.get('install-private.sh')===digest(installer)&&listed.get('release.json')===digest(metadata),'release_checksum_mismatch');
 if(version==='1.0.5')requireValue(digest(installer)===oldInstallerSHA,'old_installer_pin_mismatch');
 const release=JSON.parse(metadata.toString('utf8'));
 requireValue(release&&Object.keys(release).length===3&&['image','source_commit','version'].every(name=>Object.hasOwn(release,name)),'invalid_release_metadata');
 requireValue(release.version===version&&/^[a-f0-9]{40}$/.test(release.source_commit),'invalid_release_identity');
 requireValue(new RegExp('^ghcr\\.io/milvago-ai/milvago-server:'+version.replaceAll('.','\\.')+'@sha256:[a-f0-9]{64}$').test(release.image),'invalid_release_image');
 const text=installer.toString('utf8');
 for(const [name,value] of [['MILVAGO_RELEASE_VERSION',version],['SOURCE_COMMIT',release.source_commit],['IMAGE',release.image]]){
  const matches=[...text.matchAll(new RegExp('^'+name+"='([^'\\r\\n]+)'$",'gm'))];
  requireValue(matches.length===1&&matches[0][1]===value,'installer_metadata_mismatch');
 }
 return {...release,installer_sha256:digest(installer),metadata_sha256:digest(metadata)};
}

async function publicAsset(version,name,maximum){
 let url=new URL(official+'v'+version+'/'+name);
 for(let hop=0;hop<3;hop++){
  requireValue(url.protocol==='https:'&&!url.username&&!url.password&&!url.port&&
   (url.hostname==='github.com'||url.hostname==='release-assets.githubusercontent.com'),'asset_redirect_refused');
  const response=await fetch(url,{redirect:'manual',signal:AbortSignal.timeout(30000)});
  if([301,302,303,307,308].includes(response.status)){
   const location=response.headers.get('location');requireValue(location,'asset_redirect_missing');
   await response.body?.cancel();url=new URL(location,url);continue;
  }
  requireValue(response.status===200&&response.body,'asset_download_failed');
  const reader=response.body.getReader(),chunks=[];let size=0;
  try{
   while(true){const item=await reader.read();if(item.done)break;size+=item.value.length;
    requireValue(size<=maximum,'asset_download_too_large');chunks.push(item.value);}
  }finally{await reader.cancel();}
  return Buffer.concat(chunks,size);
 }
 throw Error('asset_redirect_limit');
}

function envEntries(content){
 const entries=new Map();
 for(const line of content.toString('utf8').split(/\r?\n/)){
  if(!line||line.startsWith('#'))continue;
  const match=/^([A-Z_][A-Z0-9_]*)=(.*)$/.exec(line);
  requireValue(match&&!entries.has(match[1]),'invalid_owned_environment');entries.set(match[1],match[2]);
 }
 return entries;
}

async function main(){
 const proof={schema:1,success:false,checks:{}};
 const proofDirectory=resolve('public-installer-proof');mkdirSync(proofDirectory,{recursive:true});
 let stage='validate_inputs',workspace,root,project,env,cleanupOK=true,exitStatus=0;
 const deadline=Date.now()+29*60*1000;
 const run=(command,args,timeout=60000)=>{
  const remaining=deadline-Date.now();requireValue(remaining>0,'qualification_deadline');
  const bounded=Math.min(timeout,remaining);
  const result=spawnSync('/usr/bin/timeout',['--signal=TERM','--kill-after=15s',Math.ceil(bounded/1000)+'s',command,...args],{cwd:root&&existsSync(root)?root:workspace,env,stdio:['ignore','pipe','pipe'],maxBuffer:4*1024*1024,timeout:bounded+20000,killSignal:'SIGKILL'});
  if(result.error||result.status!==0){const failure=Error('child_failed');failure.exitStatus=result.status;throw failure;}
  return result.stdout;
 };
 const docker=(...args)=>run('/usr/bin/docker',args);
 const compose=(...args)=>docker('compose','-p',project,'-f',join(root,'compose.yaml'),'-f',join(root,'.local/generated/compose.private.yaml'),...args);
 const database=()=>{const id=compose('ps','-q','database').toString().trim();requireValue(/^[a-f0-9]{12,64}$/.test(id),'database_container_missing');return id;};
 const sql=query=>docker('exec','-e','PGCONNECT_TIMEOUT=5','-e','PGOPTIONS=-c statement_timeout=5000',database(),'psql','-X','-v','ON_ERROR_STOP=1','-U','postgres','-d','milvago','-At','-c',query).toString().trim();
 const fileHashes=names=>Object.fromEntries(names.map(name=>[name,digest(readFileSync(join(root,name)))]));
 const protectedNames=['compose.yaml','.local/generated/realm.json','.local/generated/compose.private.yaml','.local/generated/Caddyfile.private'];
 const baseNames=['compose.yaml','.local/generated/realm.json'];
 const marker=randomBytes(24).toString('hex'),origin='http://127.0.0.1:4020';
 const volumeName=()=>{
  const mounts=JSON.parse(docker('inspect','--format','{{json .Mounts}}',database()));
  const volume=mounts.find(item=>item.Destination==='/var/lib/postgresql');
  requireValue(volume?.Type==='volume'&&typeof volume.Name==='string'&&volume.Name.startsWith(project+'_'),'unexpected_database_volume');
  return volume.Name;
 };
 const state=()=>({files:fileHashes(protectedNames),environment:envEntries(readFileSync(join(root,'.env'))),volume:volumeName(),
  origin:sql('SELECT public_url FROM public.app_config WHERE singleton AND public_url_confirmed'),
  marker:sql('SELECT marker FROM public.installer_qualification_marker'),
  image:JSON.parse(compose('config','--format','json')).services.application.image});
 const compareState=(before,after,allFiles)=>{
  for(const name of allFiles?protectedNames:baseNames)requireValue(before.files[name]===after.files[name],'preserved_configuration_changed');
  for(const [key,value]of before.environment)requireValue(after.environment.get(key)===value,'existing_environment_value_changed');
  requireValue(before.volume===after.volume&&before.origin===after.origin&&after.origin===origin&&before.marker===after.marker&&after.marker===marker,'database_state_changed');
 };
 const runInstaller=(asset,url,expectedRefusal=false)=>{
  const installerEnv={...env,MILVAGO_DIR:root};
  if(url!==undefined)installerEnv.MILVAGO_PUBLIC_URL=url;
  const remaining=deadline-Date.now();requireValue(remaining>0,'qualification_deadline');
  const bounded=Math.min(expectedRefusal?5*60*1000:12*60*1000,remaining);
  const result=spawnSync('/usr/bin/timeout',['--signal=TERM','--kill-after=15s',Math.ceil(bounded/1000)+'s','/usr/bin/bash',asset],{cwd:workspace,env:installerEnv,stdio:['ignore','pipe','pipe'],maxBuffer:4*1024*1024,timeout:bounded+20000,killSignal:'SIGKILL'});
  if(expectedRefusal){requireValue(!result.error&&result.status===1&&Buffer.concat([result.stdout??Buffer.alloc(0),result.stderr??Buffer.alloc(0)]).toString().includes('instance already uses'),'conflicting_url_not_refused');return;}
  if(result.error||result.status!==0){const failure=Error('installer_failed');failure.exitStatus=result.status;throw failure;}
 };
 const ready=async()=>{
  for(let attempt=0;attempt<30;attempt++){
   try{const response=await fetch(origin+'/readyz',{signal:AbortSignal.timeout(2000),redirect:'error'});await response.body?.cancel();if(response.status===200)return;}catch{}
   await new Promise(resolve=>setTimeout(resolve,1000));
  }
  throw Error('ready_failed');
 };
 const checkImage=release=>{
  const config=JSON.parse(compose('config','--format','json'));
  requireValue(config.services.application.image===release.image&&config.services.application.environment.APP_URL===origin&&config.services.identity.environment.KC_HOSTNAME===origin,'runtime_release_or_origin_mismatch');
  const application=compose('ps','-q','application').toString().trim();requireValue(/^[a-f0-9]{12,64}$/.test(application),'application_container_missing');
  const actual=JSON.parse(docker('inspect',application))[0];
  const image=JSON.parse(docker('image','inspect',release.image))[0];
  requireValue(actual.Config.Image===release.image&&actual.Image===image.Id&&image.Config.Labels?.['org.opencontainers.image.revision']===release.source_commit,'running_image_mismatch');
 };
 try{
  requireValue(process.platform==='linux'&&process.env.GITHUB_ACTIONS==='true'&&process.env.RUNNER_OS==='Linux','hosted_linux_required');
  const version=qualificationVersion(process.env.CHECK_PUBLIC_INSTALLER_VERSION);
  const scenario=process.env.CHECK_PUBLIC_INSTALLER_SCENARIO;requireValue(['fresh','upgrade105'].includes(scenario),'invalid_scenario');
  const temporary=process.env.RUNNER_TEMP;requireValue(temporary&&isAbsolute(temporary),'owned_temporary_parent_required');
  const parent=realpathSync(temporary);workspace=mkdtempSync(join(parent,'milvago-public-installer-'));root=join(workspace,'instance');
  requireValue(relative(parent,workspace).startsWith('milvago-public-installer-')&&!relative(parent,workspace).includes(sep),'owned_temporary_path_required');
  mkdirSync(join(workspace,'home'));mkdirSync(join(workspace,'tmp'));
  project='milvago-public-proof-'+randomBytes(8).toString('hex');
  env={PATH:'/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin',HOME:join(workspace,'home'),TMPDIR:join(workspace,'tmp'),LANG:'C.UTF-8',COMPOSE_PROJECT_NAME:project};
  proof.version=version;proof.scenario=scenario;
  stage='require_unprivileged_docker_access';docker('info','--format','{{.ServerVersion}}');
  const load=async version=>{
   const [installer,metadata,sums]=await Promise.all([publicAsset(version,'install-private.sh',2*1024*1024),publicAsset(version,'release.json',16384),publicAsset(version,'SHA256SUMS',16384)]);
   const release=verifyPublicRelease(version,installer,metadata,sums),path=join(workspace,'installer-'+version+'.sh');
   writeFileSync(path,installer,{mode:0o700,flag:'wx'});return {path,release};
  };
  stage='download_target';const target=await load(version);proof.target_release=target.release;
  stage='download_initial';const initial=scenario==='fresh'?target:await load('1.0.5');proof.initial_release=initial.release;
  stage='install_initial';runInstaller(initial.path,origin);await ready();checkImage(initial.release);proof.checks.initial_ready=true;
  stage='prepare_owned_database_marker';
  const environmentPath=join(root,'.env'),existingEnvironment=readFileSync(environmentPath);
  writeFileSync(environmentPath,Buffer.concat([existingEnvironment,Buffer.from('\nINSTALLER_QUALIFICATION_SENTINEL='+marker+'\n')]));
  sql("UPDATE public.app_config SET public_url='"+origin+"',public_url_confirmed=true WHERE singleton");
  requireValue(sql('SELECT public_url FROM public.app_config WHERE singleton AND public_url_confirmed')===origin,'fixture_origin_not_confirmed');
  sql("CREATE TABLE public.installer_qualification_marker(marker text NOT NULL); INSERT INTO public.installer_qualification_marker VALUES('"+marker+"')");
  const before=state();requireValue(before.marker===marker&&before.origin===origin,'fixture_marker_missing');
  stage='stop_preserving_volume';compose('down','--remove-orphans');
  stage='rerun_target_without_url';runInstaller(target.path,undefined);await ready();checkImage(target.release);
  stage='verify_preserved_state';const after=state();compareState(before,after,scenario==='fresh');requireValue(after.image===target.release.image,'updated_image_not_selected');
  if(scenario==='upgrade105')requireValue(before.image!==after.image,'upgrade_did_not_change_image');
  proof.checks.confirmed_url_reused=true;proof.checks.existing_environment_preserved=true;proof.checks.realm_and_base_preserved=true;proof.checks.database_marker_and_volume_preserved=true;proof.checks.target_image_running=true;proof.checks.target_ready=true;
  proof.base_compose_sha256=after.files['compose.yaml'];proof.realm_sha256=after.files['.local/generated/realm.json'];
  stage='reject_conflicting_url';runInstaller(target.path,'http://localhost:4020',true);
  stage='verify_refusal_preserved_state';const refused=state();compareState(after,refused,true);requireValue(refused.image===after.image,'refusal_changed_image');checkImage(target.release);await ready();
  proof.checks.conflicting_url_refused=true;proof.checks.refusal_preserved_protected_state=true;
  proof.success=true;
 }catch(error){proof.failure_stage=stage;proof.child_exit_status=Number.isInteger(error?.exitStatus)?error.exitStatus:null;exitStatus=1;
 }finally{
  if(root&&project&&existsSync(join(root,'compose.yaml'))){
   // Destructive cleanup is confined to this random project and its owned checkout.
   const args=['compose','-p',project,'-f',join(root,'compose.yaml')];
   if(existsSync(join(root,'.local/generated/compose.private.yaml')))args.push('-f',join(root,'.local/generated/compose.private.yaml'));
   args.push('--profile','development-mail','down','-v','--remove-orphans');
   const result=spawnSync('/usr/bin/docker',args,{cwd:root,env,stdio:'ignore',timeout:120000,killSignal:'SIGKILL'});cleanupOK=!result.error&&result.status===0;
  }
  proof.checks.owned_project_cleanup=cleanupOK;if(!cleanupOK){proof.success=false;exitStatus=1;}
  // Only these allowlisted public refs, hashes and booleans leave the disposable VM.
  writeFileSync(join(proofDirectory,'proof.json'),JSON.stringify(proof,null,2)+'\n',{mode:0o600});
  if(workspace)rmSync(workspace,{recursive:true,force:true});
  console.log(proof.success?'Public installer qualification passed.':'Public installer qualification failed; inspect safe proof.json.');
  process.exitCode=exitStatus;
 }
}

if(process.argv[1]&&import.meta.url===pathToFileURL(resolve(process.argv[1])).href)await main();
