import { appendFileSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';

export function releaseVersion(value) {
  const version = value.trim();
  if (!/^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/.test(version)) throw new Error('VERSION must contain an exact X.Y.Z version.');
  return version;
}

export function releaseImage(branch, version, revision) {
  releaseVersion(version);
  if (!/^[a-f0-9]{40}$/.test(revision)) throw new Error('Expected a full source commit.');
  if (branch === 'main') return `ghcr.io/milvago-ai/milvago-server:${version}`;
  if (branch === 'dev') return `ghcr.io/milvago-ai/milvago-server-dev:sha-${revision}`;
  throw new Error('Images can only be published from dev or main.');
}

export function newerVersion(next, previous) {
  const a = releaseVersion(next).split('.').map(BigInt);
  const b = releaseVersion(previous).split('.').map(BigInt);
  for (let i = 0; i < 3; i++) { if (a[i] !== b[i]) return a[i] > b[i]; }
  return false;
}

export function unpublishedWorkflowRecovery(next, previous, tagged, paths) {
  // Repair publication tooling before the first immutable release, without changing its runtime.
  const allowed = new Set(['.github/workflows/ghcr.yml', 'scripts/server-release.mjs', 'scripts/server-release.test.mjs']);
  return next === previous && !tagged && paths.length > 0 && paths.every(path => allowed.has(path));
}

export function requiresRelease(paths) {
  // These files do not enter the runtime image or the published installer.
  const publicationOnly = new Set(['README.md', 'INSTALL.md', '.github/workflows/ci.yml', 'scripts/server-release.mjs', 'scripts/server-release.test.mjs',
    '.github/workflows/public-installer-qualification.yml', 'scripts/check-public-installer.mjs', 'scripts/check-public-installer.test.mjs']);
  return paths.some(path => !publicationOnly.has(path));
}

export function renderInstaller(template, version, revision, digest) {
  const image = releaseImage('main', version, revision);
  if (!/^sha256:[a-f0-9]{64}$/.test(digest)) throw new Error('Expected an immutable image digest.');
  if (!template.includes(`MILVAGO_RELEASE_VERSION='${version}'`)) throw new Error('Installer and VERSION disagree.');
  for (const marker of ['@SOURCE_COMMIT@', '@IMAGE@']) {
    if (template.split(marker).length !== 2) throw new Error('Expected one installer marker: ' + marker);
  }
  return template.replace('@SOURCE_COMMIT@', revision).replace('@IMAGE@', image + '@' + digest);
}

// Release checks execute the system Git installation without searching PATH.
const gitExecutable = process.platform === 'win32' ? 'C:/Program Files/Git/cmd/git.exe' : '/usr/bin/git';
const git = (...args) => execFileSync(gitExecutable, args, { encoding:'utf8', stdio:['ignore','pipe','pipe'] }).trim();

function releaseRequired() {
  let base;
  if (process.env.GITHUB_BASE_REF === 'main') base = 'origin/main';
  else if (process.env.GITHUB_EVENT_PATH) {
    const event = JSON.parse(readFileSync(process.env.GITHUB_EVENT_PATH,'utf8'));
    if (/^[a-f0-9]{40}$/.test(event.before) && event.before !== '0'.repeat(40)) base = event.before;
  }
  // An unknown baseline must never suppress a release or its version checks.
  if (!base) return true;
  return requiresRelease(git('diff','--name-only','--no-renames',base,'HEAD').split('\n').filter(Boolean));
}

function check() {
  const version = releaseVersion(readFileSync('VERSION','utf8'));
  renderInstaller(readFileSync('install-private.sh','utf8'), version, 'a'.repeat(40), 'sha256:'+'b'.repeat(64));
  if (!releaseRequired()) {
    console.log('Publication-only change: retain the existing immutable release.');
    return;
  }
  const production = process.env.GITHUB_REF === 'refs/heads/main';
  if (production || process.env.GITHUB_BASE_REF === 'main') {
    const base = production ? 'HEAD^1' : 'origin/main';
    // The first versioned release has no VERSION in its parent.
    if (git('ls-tree','--name-only',base).split('\n').includes('VERSION')) {
      const previous = releaseVersion(git('show',`${base}:VERSION`));
      const tagged = Boolean(git('tag','--list',`v${version}`));
      const paths = git('diff','--name-only',base,'HEAD').split('\n').filter(Boolean);
      if (!newerVersion(version, previous) && !unpublishedWorkflowRecovery(version, previous, tagged, paths)) throw new Error('A merge to main requires a new server version.');
    }
    if (git('tag','--list',`v${version}`) && git('rev-list','-n','1',`v${version}`) !== git('rev-parse','HEAD')) throw new Error('This release version already belongs to another commit.');
  }
  console.log('Release policy passed for ' + version);
}

async function metadata() {
  const version = releaseVersion(readFileSync('VERSION','utf8'));
  const branch = process.env.GITHUB_REF_NAME;
  const image = releaseImage(branch,version,process.env.GITHUB_SHA);
  const pkg = branch === 'main' ? 'milvago-server' : 'milvago-server-dev';
  const values = {version,image,package:pkg,production:String(branch==='main')};
  const repository = `milvago-ai/${pkg}`;
  const auth = await fetch(`https://ghcr.io/token?service=ghcr.io&scope=repository:${repository}:pull`, {
    headers:{Authorization:'Basic '+Buffer.from(`${process.env.GITHUB_ACTOR}:${process.env.GH_TOKEN}`).toString('base64')},redirect:'error',
  });
  if (!auth.ok) throw new Error('Registry authorization failed: HTTP '+auth.status);
  const {token} = await auth.json();
  if (!token) throw new Error('Registry did not return an access token.');
  const manifest = await fetch(`https://ghcr.io/v2/${repository}/manifests/${image.split(':').at(-1)}`, {
    headers:{Authorization:'Bearer '+token,Accept:'application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.v2+json'},redirect:'error',
  });
  if (manifest.status === 404) values.existing = '';
  else if (manifest.ok) {
    const digest = manifest.headers.get('docker-content-digest');
    if (!/^sha256:[a-f0-9]{64}$/.test(digest)) throw new Error('Registry returned an invalid digest.');
    values.existing = image+'@'+digest;
  } else throw new Error('Cannot determine whether the immutable tag exists: HTTP '+manifest.status);
  appendFileSync(process.env.GITHUB_OUTPUT,Object.entries(values).map(([k,v])=>`${k}=${v}\n`).join(''));
}

function render() {
  const version = releaseVersion(readFileSync('VERSION','utf8'));
  const revision = process.env.GITHUB_SHA;
  const digest = process.env.IMAGE_DIGEST;
  const installer = renderInstaller(readFileSync('install-private.sh','utf8'),version,revision,digest);
  mkdirSync('release',{recursive:true});
  writeFileSync('release/install-private.sh',installer,{mode:0o755});
  writeFileSync('release/release.json',JSON.stringify({version,source_commit:revision,image:releaseImage('main',version,revision)+'@'+digest},null,2)+'\n');
  const sums = ['install-private.sh','release.json'].map(name=>createHash('sha256').update(readFileSync('release/'+name)).digest('hex')+'  '+name+'\n').join('');
  writeFileSync('release/SHA256SUMS',sums);
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  const command = process.argv[2];
  if (command === 'check') check();
  else if (command === 'scope') appendFileSync(process.env.GITHUB_OUTPUT,`release_required=${releaseRequired()}\n`);
  else if (command === 'metadata') await metadata();
  else if (command === 'render') render();
  else throw new Error('Expected check, scope, metadata or render.');
}
