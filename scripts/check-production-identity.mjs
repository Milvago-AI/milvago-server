import {readFileSync} from 'node:fs';
const secret=readFileSync('/work/.env','utf8').split('\n').find(line=>line.startsWith('IDENTITY_ADMIN_PASSWORD=')).split('=')[1];
const base='http://127.0.0.1:8080';
const form=new URLSearchParams({grant_type:'password',client_id:'admin-cli',username:'bootstrap-admin'});
form.set('password',secret);
const response=await fetch(base+'/realms/master/protocol/openid-connect/token',{method:'POST',body:form});
if(!response.ok)throw Error('Admin authentication failed');
const token=(await response.json()).access_token;
const headers={Authorization:'Bearer '+token,'Content-Type':'application/json'};
const action=process.argv[2];
if(action==='set'){
 const smtpServer=JSON.parse(process.argv[3]);
 const result=await fetch(base+'/admin/realms/milvago',{method:'PUT',headers,body:JSON.stringify({smtpServer})});
 if(!result.ok)throw Error('SMTP fixture failed');
}else if(action==='get'){
 const result=await fetch(base+'/admin/realms/milvago',{headers});
 if(!result.ok)throw Error('Realm read failed');
 console.log(JSON.stringify((await result.json()).smtpServer));
}else throw Error('Expected set or get');
