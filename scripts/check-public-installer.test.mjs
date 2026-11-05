import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {qualificationVersion,verifyPublicRelease} from './check-public-installer.mjs';
const sha=bytes=>createHash('sha256').update(bytes).digest('hex');
function fixture(change={}){
 const metadata=Buffer.from(JSON.stringify({version:'1.1.1',source_commit:'a'.repeat(40),image:'ghcr.io/milvago-ai/milvago-server:1.1.1@sha256:'+'b'.repeat(64),...change}));
 const release=JSON.parse(metadata);
 const installer=Buffer.from("#!/usr/bin/env bash\nMILVAGO_RELEASE_VERSION='1.1.1'\nSOURCE_COMMIT='"+release.source_commit+"'\nIMAGE='"+release.image+"'\n");
 const sums=Buffer.from(sha(installer)+'  install-private.sh\n'+sha(metadata)+'  release.json\n');
 return {installer,metadata,sums};
}
test('qualification version has no shell or future-version interpretation',()=>{
 assert.equal(qualificationVersion('1.1.1'),'1.1.1');
 for(const version of [undefined,'1.1.1\n','1.1.1;id','$(id)','1.0.5','1.1.0','latest','1.2.0'])assert.throws(()=>qualificationVersion(version));
});
test('matching exact assets return only public release identity and hashes',()=>{
 const {installer,metadata,sums}=fixture();
 const release=verifyPublicRelease('1.1.1',installer,metadata,sums);
 assert.equal(release.version,'1.1.1');assert.equal(release.installer_sha256,sha(installer));
 assert.equal(release.metadata_sha256,sha(metadata));assert.equal(Object.keys(release).length,5);
});
for(const [name,change]of Object.entries({version:{version:'1.0.5'},source:{source_commit:'main'},image:{image:'ghcr.io/other/image:1.1.1@sha256:'+'b'.repeat(64)},extra:{unexpected:'private-value'}})){
 test('coherently checksummed invalid metadata refuses: '+name,()=>{
  const {installer,metadata,sums}=fixture(change);assert.throws(()=>verifyPublicRelease('1.1.1',installer,metadata,sums));
 });
}
test('mismatching installer binding refuses even with recomputed checksums',()=>{
 const {installer,metadata}=fixture();
 const modified=Buffer.from(installer.toString().replace('SOURCE_COMMIT=', 'UNBOUND_SOURCE_COMMIT='));
 const sums=Buffer.from(sha(modified)+'  install-private.sh\n'+sha(metadata)+'  release.json\n');
 assert.throws(()=>verifyPublicRelease('1.1.1',modified,metadata,sums));
});
test('changed bytes, duplicate entries, unexpected names and old pin mismatch refuse',()=>{
 const {installer,metadata,sums}=fixture();
 assert.throws(()=>verifyPublicRelease('1.1.1',Buffer.concat([installer,Buffer.from('x')]),metadata,sums));
 const row=sha(installer)+'  install-private.sh\n';
 for(const invalid of [row+row,sums.toString()+row,sums.toString().replace('release.json','../../release.json')])assert.throws(()=>verifyPublicRelease('1.1.1',installer,metadata,Buffer.from(invalid)));
 assert.throws(()=>verifyPublicRelease('1.0.5',installer,metadata,sums));
});
