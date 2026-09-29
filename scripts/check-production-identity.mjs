import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
const secret=readFileSync('/work/.env','utf8').split('\n').find(line=>line.startsWith('IDENTITY_ADMIN_PASSWORD=')).split('=')[1];
const base='http://127.0.0.1:8080';
const form=new URLSearchParams({grant_type:'password',client_id:'admin-cli',username:'bootstrap-admin'});
form.set('password',secret);
const response=await fetch(base+'/realms/master/protocol/openid-connect/token',{method:'POST',body:form});
if(!response.ok)throw new Error('Admin authentication failed');
const token=(await response.json()).access_token;
const headers={Authorization:'Bearer '+token,'Content-Type':'application/json'};
const action=process.argv[2];
if(action==='discovery'){
 const result=await fetch(base+'/realms/milvago/.well-known/openid-configuration');
 if(!result.ok)throw new Error('OIDC discovery failed');
 assert.equal((await result.json()).issuer,process.argv[3]+'/realms/milvago');
}else if(action==='set'){
 const smtpServer=JSON.parse(process.argv[3]);
 const result=await fetch(base+'/admin/realms/milvago',{method:'PUT',headers,body:JSON.stringify({smtpServer})});
 if(!result.ok)throw new Error('SMTP fixture failed');
}else if(action==='verify'){
 const result=await fetch(base+'/admin/realms/milvago',{headers});
 if(!result.ok)throw new Error('Realm read failed');
 const expected=JSON.parse(process.argv[3]);
 const current=(await result.json()).smtpServer;
 for(const [key,value] of Object.entries(expected))assert.equal(current[key],value);
}else throw new Error('Expected set, verify or discovery');
