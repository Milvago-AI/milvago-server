import test from 'node:test';
import assert from 'node:assert/strict';
import { releaseVersion, releaseImage, newerVersion, renderInstaller } from './server-release.mjs';

test('release versions exclude floating tags and ambiguous versions', () => {
  assert.equal(releaseVersion('1.0.0\n'),'1.0.0');
  for(const input of ['latest','1.0','v1.0.0','01.0.0','1.0.0-dev','1.0.0\n2.0.0']) assert.throws(()=>releaseVersion(input));
  assert.equal(newerVersion('1.10.0','1.9.9'),true);
  assert.equal(newerVersion('1.0.0','1.0.0'),false);
  assert.equal(newerVersion('0.9.9','1.0.0'),false);
});

test('production and development use separate packages', () => {
  const sha='a'.repeat(40);
  assert.equal(releaseImage('main','1.0.0',sha),'ghcr.io/milvago-ai/milvago-server:1.0.0');
  assert.equal(releaseImage('dev','1.0.0',sha),'ghcr.io/milvago-ai/milvago-server-dev:sha-'+sha);
  assert.throws(()=>releaseImage('feature','1.0.0',sha));
  assert.throws(()=>releaseImage('main','1.0.0','main'));
});

test('generated installers bind a version to a source commit and digest', () => {
  const template="MILVAGO_RELEASE_VERSION='1.0.0'\nSOURCE_COMMIT='@SOURCE_COMMIT@'\nIMAGE='@IMAGE@'\n";
  const sha='a'.repeat(40),digest='sha256:'+'b'.repeat(64);
  const rendered=renderInstaller(template,'1.0.0',sha,digest);
  assert.ok(rendered.includes(`SOURCE_COMMIT='${sha}'`));
  assert.ok(rendered.includes(`IMAGE='ghcr.io/milvago-ai/milvago-server:1.0.0@${digest}'`));
  assert.throws(()=>renderInstaller(template,'1.1.0',sha,digest));
  assert.throws(()=>renderInstaller(template,'1.0.0',sha,'latest'));
  assert.throws(()=>renderInstaller(template+'@IMAGE@','1.0.0',sha,digest));
});
