#!/usr/bin/env bash
set -euo pipefail

SOURCE_COMMIT='01ec3ee9dcc270360d07eaac33ef9554a433481b'
IMAGE='ghcr.io/milvago-ai/milvago-community-server@sha256:da2ac77cdd471e884f994f79344472225bc64e67a294b71ad43d84021e066563'
COSIGN_IMAGE='ghcr.io/sigstore/cosign/cosign:v3.1.3@sha256:9e5c2f2edc34351160407ca3416c61855bdf9403c3c5936e0f0be7fc261611b8'
CADDY_IMAGE='caddy:2.11.4-alpine@sha256:6aeddd44c3078b0f9a35206472a11420648a79c184603ef95957d0a20044cb2b'
NODE_IMAGE='node:26.10.0-bookworm-slim@sha256:662933cf47f013bc8e4beb31a6116448427a82057ba7c42c97e4c5ba766504c2'
APT_KEY_SHA256='1500c1f56fa9e26b9b8f42452a553675796ade0807cdce11975eb98170b3a570'
RPM_KEY_SHA256='e6c650e0700b1bf4868b693b30761b926844befc8a0acb7ac0dd9b1faf1b7423'

fail() { printf 'Error: %s\n' "$*" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || fail "Required command is missing: $1"; }
as_root() {
  if (( EUID == 0 )); then "$@"; else sudo "$@"; fi
}
fetch() {
  if command -v curl >/dev/null 2>&1; then
    curl -fsSL "$1" -o "$2"
  elif command -v wget >/dev/null 2>&1; then
    wget -qO "$2" "$1"
  else
    fail 'curl or wget is required to add the official Docker repository.'
  fi
}
verify_key() {
  local expected=$1
  local file=$2
  printf '%s  %s\n' "$expected" "$file" | sha256sum -c - >/dev/null ||
    fail 'The downloaded Docker repository key has an unexpected SHA-256.'
}

install_apt() {
  need apt-get
  need dpkg
  need sha256sum
  local codename=${VERSION_CODENAME:-}
  [[ -n "$codename" ]] || fail 'Cannot determine the Debian or Ubuntu release.'
  if [[ "$ID" == ubuntu ]]; then
    codename=${UBUNTU_CODENAME:-$codename}
  fi
  local key_file
  key_file=$(mktemp)
  fetch "https://download.docker.com/linux/$ID/gpg" "$key_file"
  verify_key "$APT_KEY_SHA256" "$key_file"
  as_root install -m 0755 -d /etc/apt/keyrings
  as_root install -m 0644 "$key_file" /etc/apt/keyrings/docker.asc
  rm -f -- "$key_file"
  if [[ ! -f /etc/apt/sources.list.d/docker.sources ]]; then
    local source_file
    source_file=$(mktemp)
    cat > "$source_file" <<EOF
Types: deb
URIs: https://download.docker.com/linux/$ID
Suites: $codename
Components: stable
Architectures: $(dpkg --print-architecture)
Signed-By: /etc/apt/keyrings/docker.asc
EOF
    as_root install -m 0644 "$source_file" /etc/apt/sources.list.d/docker.sources
    rm -f -- "$source_file"
  fi
  as_root apt-get update
  if (( install_engine )); then
    as_root apt-get install -y --no-install-recommends --no-remove \
      docker-ce docker-ce-cli containerd.io docker-compose-plugin
  else
    as_root apt-get install -y --no-install-recommends --no-remove docker-compose-plugin
  fi
}

install_dnf() {
  need dnf
  need rpm
  need sha256sum
  local repo_id repo_release
  if [[ "$ID" == fedora ]]; then
    [[ "${VERSION_ID:-}" =~ ^[0-9]+$ ]] || fail 'Cannot determine the Fedora release.'
    repo_id='fedora'
    repo_release=$VERSION_ID
  else
    local major=${VERSION_ID:-}
    major=${major%%.*}
    [[ "$major" =~ ^(8|9|10)$ ]] ||
      fail "Docker RPM repositories are configured for RHEL-compatible releases 8, 9 and 10 only (detected: ${VERSION_ID:-unknown})."
    case "$ID" in
      rhel|centos|rocky|almalinux|ol) ;;
      *)
        [[ " ${ID_LIKE:-} " == *' rhel '* || " ${ID_LIKE:-} " == *' centos '* ]] ||
          fail "Automatic Docker installation is not supported on ${ID:-unknown}."
        ;;
    esac
    repo_release=$major
    if [[ "$ID" == rhel || "$major" == 8 ]]; then
      repo_id='rhel'
    else
      repo_id='centos'
    fi
  fi
  local key_file
  key_file=$(mktemp)
  fetch "https://download.docker.com/linux/$repo_id/gpg" "$key_file"
  verify_key "$RPM_KEY_SHA256" "$key_file"
  as_root install -m 0755 -d /etc/pki/rpm-gpg
  as_root install -m 0644 "$key_file" /etc/pki/rpm-gpg/RPM-GPG-KEY-milvago-docker
  rm -f -- "$key_file"
  as_root rpm --import /etc/pki/rpm-gpg/RPM-GPG-KEY-milvago-docker
  if [[ ! -f /etc/yum.repos.d/docker-ce.repo ]]; then
    local repo_file
    repo_file=$(mktemp)
    cat > "$repo_file" <<EOF
[docker-ce-stable]
name=Docker CE Stable
baseurl=https://download.docker.com/linux/$repo_id/$repo_release/\$basearch/stable
enabled=1
gpgcheck=1
gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-milvago-docker
EOF
    as_root install -m 0644 "$repo_file" /etc/yum.repos.d/docker-ce.repo
    rm -f -- "$repo_file"
  fi
  if (( install_engine )); then
    as_root dnf -y --setopt=install_weak_deps=False install \
      docker-ce docker-ce-cli containerd.io docker-compose-plugin
  else
    as_root dnf -y --setopt=install_weak_deps=False install docker-compose-plugin
  fi
}

compose_supports_reset() {
  local probe
  probe=$(mktemp -d "${TMPDIR:-/tmp}/milvago-compose.XXXXXXXX") || return 1
  cat > "$probe/compose.yaml" <<EOF
services:
  probe:
    build: .
    image: $IMAGE
EOF
  cat > "$probe/override.yaml" <<'EOF'
services:
  probe:
    build: !reset null
    ports: !override
      - "127.0.0.1:4021:4020"
EOF
  local status=0
  docker compose -f "$probe/compose.yaml" -f "$probe/override.yaml" config --quiet >/dev/null 2>&1 || status=1
  rm -rf -- "$probe"
  return "$status"
}

start_docker() {
  if command -v systemctl >/dev/null 2>&1; then
    as_root systemctl enable --now docker
  elif command -v service >/dev/null 2>&1; then
    as_root service docker start
  else
    fail 'Docker was installed but no supported service manager could start it.'
  fi
}

run_docker() {
  if (( docker_as_root )); then
    if [[ -n "${DOCKER_CONFIG:-}" ]]; then
      as_root env "DOCKER_CONFIG=$DOCKER_CONFIG" docker "$@"
    else
      as_root docker "$@"
    fi
  else
    docker "$@"
  fi
}

private_ipv4() {
  local address=$1
  [[ "$address" =~ ^(0|[1-9][0-9]{0,2})(\.(0|[1-9][0-9]{0,2})){3}$ ]] || return 1
  local a b c d
  IFS=. read -r a b c d <<< "$address"
  (( a <= 255 && b <= 255 && c <= 255 && d <= 255 )) || return 1
  (( a == 10 || (a == 172 && b >= 16 && b <= 31) || (a == 192 && b == 168) ))
}

detect_host_ip() {
  local address=${MILVAGO_HOST_IP:-}
  if [[ -n "$address" ]]; then
    private_ipv4 "$address" || fail 'MILVAGO_HOST_IP must be a private IPv4 address.'
    printf '%s' "$address"
    return
  fi
  if command -v ip >/dev/null 2>&1; then
    local route
    route=$(ip -4 route get 1.1.1.1 2>/dev/null) || route=''
    if [[ "$route" =~ [[:space:]]src[[:space:]]([0-9.]+) ]]; then
      address=${BASH_REMATCH[1]}
    fi
  fi
  if ! private_ipv4 "$address" && command -v hostname >/dev/null 2>&1; then
    local candidate
    for candidate in $(hostname -I 2>/dev/null); do
      if private_ipv4 "$candidate"; then address=$candidate; break; fi
    done
  fi
  private_ipv4 "$address" ||
    fail 'No private IPv4 address was found. Set MILVAGO_HOST_IP to this server LAN address.'
  printf '%s' "$address"
}

host_ip=$(detect_host_ip)

base_tools=(uname dirname mktemp id mkdir mv rm cat env chown chmod ln)
missing_tools=()
for tool in "${base_tools[@]}"; do
  command -v "$tool" >/dev/null 2>&1 || missing_tools+=("$tool")
done
(( ${#missing_tools[@]} == 0 )) ||
  fail "Base Linux utilities are missing: ${missing_tools[*]}. Install the distribution's coreutils package."
[[ "$(uname -s)" == Linux ]] || fail 'This installer requires Linux.'
umask 077
stage=''
auth_dir=''
cleanup() {
  if [[ -n "$stage" && -d "$stage" ]]; then rm -rf -- "$stage"; fi
  if [[ -n "$auth_dir" && -d "$auth_dir" ]]; then rm -rf -- "$auth_dir"; fi
}
trap cleanup EXIT
complete_checkout() {
  [[ -f "$1/compose.yaml" && -f "$1/scripts/local-init.mjs" && -f "$1/cosign.pub" ]]
}
script_root=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
if [[ -n "${MILVAGO_DIR:-}" ]]; then
  root=$MILVAGO_DIR
elif complete_checkout "$script_root"; then
  root=$script_root
else
  root="$HOME/milvago-community"
fi
[[ "$root" == /* ]] || fail 'MILVAGO_DIR must be an absolute path.'

registry_token=${GHCR_TOKEN:-}
unset GHCR_TOKEN
needs_source=0
if ! complete_checkout "$root"; then
  [[ ! -e "$root" ]] ||
    fail "The installation directory is incomplete: $root. Set MILVAGO_DIR to a new absolute path or restore this checkout."
  needs_source=1
fi

install_engine=0
install_compose=0
command -v docker >/dev/null 2>&1 || install_engine=1
if (( install_engine )) || ! docker compose version >/dev/null 2>&1 || ! compose_supports_reset; then
  install_compose=1
fi
if (( install_engine || install_compose )); then
  if (( install_engine )); then
    printf 'Installing Docker Engine and Compose from the official repository...\n'
  else
    printf 'Installing Docker Compose from the official repository...\n'
  fi
  . /etc/os-release
  case "${ID:-unknown}" in
    ubuntu|debian) installer=install_apt ;;
    fedora|rhel|centos|rocky|almalinux|ol) installer=install_dnf ;;
    *)
      if [[ " ${ID_LIKE:-} " == *' rhel '* || " ${ID_LIKE:-} " == *' centos '* ]]; then
        installer=install_dnf
      else
        fail "Automatic Docker installation is not supported on ${ID:-unknown}. Install Docker Engine and Compose with the distribution's package manager."
      fi
      ;;
  esac
  missing_tools=()
  for tool in sha256sum install; do
    command -v "$tool" >/dev/null 2>&1 || missing_tools+=("$tool")
  done
  if ! command -v curl >/dev/null 2>&1 && ! command -v wget >/dev/null 2>&1; then
    missing_tools+=('curl or wget')
  fi
  if (( install_engine )) &&
    ! command -v systemctl >/dev/null 2>&1 &&
    ! command -v service >/dev/null 2>&1; then
    missing_tools+=('systemctl or service')
  fi
  if (( EUID != 0 )); then
    command -v sudo >/dev/null 2>&1 || missing_tools+=(sudo)
  fi
  (( ${#missing_tools[@]} == 0 )) ||
    fail "Docker package installation needs missing host tools: ${missing_tools[*]}."
  if (( EUID != 0 )); then sudo -v; fi
  "$installer"
  need docker
  docker compose version >/dev/null 2>&1 || fail 'The Docker Compose plugin did not install correctly.'
  if (( install_engine )); then start_docker; fi
fi

docker_as_root=0
if ! docker info >/dev/null 2>&1; then
  if (( EUID != 0 )); then need sudo; sudo -v; fi
  if as_root docker info >/dev/null 2>&1; then
    docker_as_root=1
  else
    start_docker
    if docker info >/dev/null 2>&1; then
      docker_as_root=0
    elif as_root docker info >/dev/null 2>&1; then
      docker_as_root=1
    else
      fail 'Docker Engine is unavailable after installation or startup.'
    fi
  fi
fi
run_docker compose version >/dev/null 2>&1 || fail 'Docker Compose is unavailable.'
compose_supports_reset || fail 'Docker Compose cannot process the required !reset and !override configuration.'

if (( needs_source )); then
  if [[ -z "$registry_token" ]]; then
    [[ -r /dev/tty ]] || fail 'Set GHCR_TOKEN when no interactive terminal is available.'
    read -r -s -p 'GitHub classic token (repo, read:packages): ' registry_token </dev/tty
    printf '\n' >&2
  fi
  [[ "$registry_token" =~ ^[A-Za-z0-9_]+$ ]] || fail 'A GitHub token is required.'
  parent=$(dirname -- "$root")
  mkdir -p -- "$parent"
  stage=$(mktemp -d "$parent/.milvago-source.XXXXXXXX")
  mkdir -- "$stage/source"
  cat > "$stage/download.mjs" <<'NODE'
import { readFileSync, writeFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';

try {
  const token = readFileSync(0, 'utf8').trim();
  const revision = process.argv[2];
  const response = await fetch(
    'https://api.github.com/repos/Milvago-AI/milvago-server/tarball/' + revision,
    {
      headers: {
        Authorization: 'Bearer ' + token,
        Accept: 'application/vnd.github+json',
      },
      redirect: 'manual',
    },
  );
  if (response.status !== 302 && response.status !== 307) {
    throw new Error('Private Community source request returned HTTP ' + response.status);
  }
  const archiveURL = new URL(response.headers.get('location'));
  if (archiveURL.origin !== 'https://codeload.github.com') {
    throw new Error('Private Community source redirect was unexpected');
  }
  const archive = await fetch(archiveURL, { redirect: 'error' });
  if (!archive.ok) {
    throw new Error('Private Community source download returned HTTP ' + archive.status);
  }
  writeFileSync('/work/source.tar.gz', Buffer.from(await archive.arrayBuffer()), { mode: 0o600 });
  const unpack = spawnSync('tar', [
    '-xzf', '/work/source.tar.gz', '--strip-components=1',
    '--no-same-owner', '-C', '/work/source',
  ], { stdio: 'inherit' });
  if (unpack.status !== 0) throw new Error('Private Community source extraction failed');
} catch (error) {
  console.error('Error: ' + error.message);
  process.exitCode = 1;
}
NODE
  printf 'Fetching the pinned Community server source into %s...\n' "$root"
  printf '%s' "$registry_token" |
    run_docker run --rm -i --user "$(id -u):$(id -g)" \
      -v "$stage:/work:Z" -w /work \
      "$NODE_IMAGE" node /work/download.mjs "$SOURCE_COMMIT" ||
    fail 'The private Community source could not be downloaded and extracted. Check repository access and the repo token scope.'
  complete_checkout "$stage/source" ||
    fail 'The downloaded Community source is incomplete.'
  mv -- "$stage/source" "$root"
  rm -rf -- "$stage"
  stage=''
fi
[[ -e "$root/.env" && -f "$root/.local/generated/realm.json" ]] ||
  [[ ! -e "$root/.env" && ! -e "$root/.local/generated/realm.json" ]] ||
  fail 'Local configuration is incomplete; restore the matching .env and realm.json files before continuing.'

auth_dir=$(mktemp -d "${TMPDIR:-/tmp}/milvago-ghcr.XXXXXXXX")
original_docker_config=${DOCKER_CONFIG:-$HOME/.docker}
if [[ -d "$original_docker_config/cli-plugins" ]]; then
  plugin_dir=$(CDPATH= cd -- "$original_docker_config/cli-plugins" && pwd -P)
  ln -s -- "$plugin_dir" "$auth_dir/cli-plugins"
fi
export DOCKER_CONFIG="$auth_dir"

if [[ -z "${GHCR_USERNAME:-}" ]]; then
  [[ -r /dev/tty ]] || fail 'Set GHCR_USERNAME when no interactive terminal is available.'
  read -r -p 'GitHub username: ' GHCR_USERNAME </dev/tty
fi
[[ -n "$GHCR_USERNAME" ]] || fail 'GitHub username is required.'

if [[ -z "$registry_token" ]]; then
  [[ -r /dev/tty ]] || fail 'Set GHCR_TOKEN when no interactive terminal is available.'
  read -r -s -p 'GitHub classic token (repo, read:packages): ' registry_token </dev/tty
  printf '\n' >&2
fi
[[ "$registry_token" =~ ^[A-Za-z0-9_]+$ ]] || fail 'GitHub token is required.'
printf '%s' "$registry_token" | run_docker login ghcr.io --username "$GHCR_USERNAME" --password-stdin >/dev/null ||
  fail 'GHCR login failed. Check package access and the read:packages scope.'
printf 'Checking published Community images...\n'
latest_image=$(printf '%s' "$registry_token" | run_docker run --rm -i "$NODE_IMAGE" node -e '
(async () => {
const token = require("node:fs").readFileSync(0, "utf8").trim();
const response = await fetch(
  "https://api.github.com/orgs/Milvago-AI/packages/container/milvago-community-server/versions?per_page=100",
  { headers: { Authorization: "Bearer " + token, Accept: "application/vnd.github+json" } },
);
if (!response.ok) throw new Error("GitHub Packages returned HTTP " + response.status);
const versions = await response.json();
const published = versions
  .filter((entry) => /^sha256:[a-f0-9]{64}$/.test(entry.name) &&
    entry.metadata?.container?.tags?.some((tag) => /^sha-[a-f0-9]{40}$/.test(tag)))
  .sort((a, b) => Date.parse(b.created_at) - Date.parse(a.created_at));
if (!published.length) throw new Error("No published Community image was found");
process.stdout.write("ghcr.io/milvago-ai/milvago-community-server@" + published[0].name);
})().catch((error) => {
  console.error("Error: " + error.message);
  process.exitCode = 1;
});
') || fail 'Cannot find the latest private Community image. Check read:packages access.'
[[ "$latest_image" =~ ^ghcr[.]io/milvago-ai/milvago-community-server@sha256:[a-f0-9]{64}$ ]] ||
  fail 'GitHub Packages returned an invalid image digest.'
IMAGE=$latest_image
unset latest_image
UPDATE_PUBLIC_KEY='14ER8eA7zpdlVLLgL+7CPce5eka1Eqmp8Tmz2mUJxmg='
cat > "$root/.local/generated/fetch-agent-release.mjs" <<'NODE'
import { createHash, createPublicKey, verify } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { copyFileSync, existsSync, lstatSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, renameSync, rmSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

const root = '/work';
const target = join(root, '.local/installers');
const expectedArchive = 'd3f03490d14d921edaf907fbc14de85dbbd5dfae92248e70478d7b611e3fe390';
const expected = {
  windows: { name: 'milvago-community-0.5.51-windows.msi', size: 5824512, sha256: '83041474374d90f1e399053e5e3f05a4a32511a2848345064ad98702637db07c', format: 'msi' },
  linux: { name: 'milvago-community-0.5.51-linux.tar.gz', size: 5548553, sha256: '14a134fd987139f41a66d780021c6ff1f971e9aacefa528621611d9b5c347188', format: 'binary' },
};
const digest = bytes => createHash('sha256').update(bytes).digest('hex');
const requireValue = (condition, message) => { if (!condition) throw Error(message); };
let stage;
try {
  const token = readFileSync(0, 'utf8').trim();
  requireValue(/^[A-Za-z0-9_]+$/.test(token), 'GitHub token is missing');
  const response = await fetch('https://api.github.com/repos/Milvago-AI/milvago-agent/releases/assets/591307586', {
    headers: { Authorization: 'Bearer ' + token, Accept: 'application/octet-stream', 'X-GitHub-Api-Version': '2022-11-28' },
    redirect: 'manual',
  });
  let archiveResponse = response;
  if (response.status === 302 || response.status === 307) {
    const redirect = new URL(response.headers.get('location'));
    requireValue(redirect.protocol === 'https:' && redirect.hostname === 'release-assets.githubusercontent.com',
      'Unexpected Community agent release redirect');
    archiveResponse = await fetch(redirect, { redirect: 'error' });
  }
  requireValue(archiveResponse.ok, 'Private Community agent release returned HTTP ' + archiveResponse.status);
  const archive = Buffer.from(await archiveResponse.arrayBuffer());
  requireValue(archive.length < 32 * 1024 * 1024 && digest(archive) === expectedArchive,
    'Community agent archive digest does not match the pinned release');
  stage = mkdtempSync(join(root, '.local/generated/agent-release-'));
  const archivePath = join(stage, 'release.tar.gz');
  const unpacked = join(stage, 'contents');
  mkdirSync(unpacked);
  writeFileSync(archivePath, archive, { mode: 0o600 });
  const tar = spawnSync('tar', ['-xzf', archivePath, '--no-same-owner', '-C', unpacked], { stdio: 'pipe' });
  requireValue(tar.status === 0, 'Community agent archive could not be extracted');
  const files = readdirSync(unpacked).sort();
  const wanted = ['community-linux-update.json', 'community-linux.json', 'community-windows-update.json',
    'community-windows.json', expected.linux.name, expected.windows.name, 'release-public-key.txt'].sort();
  requireValue(JSON.stringify(files) === JSON.stringify(wanted), 'Community agent archive contains unexpected files');
  const publicKey = readFileSync(join(unpacked, 'release-public-key.txt'), 'utf8').trim();
  requireValue(publicKey === process.env.MILVAGO_UPDATE_PUBLIC_KEY, 'Community update key differs from the pinned key');
  const key = createPublicKey({
    key: Buffer.concat([Buffer.from('302a300506032b6570032100', 'hex'), Buffer.from(publicKey, 'base64')]),
    format: 'der', type: 'spki',
  });
  for (const [platform, item] of Object.entries(expected)) {
    const artifact = readFileSync(join(unpacked, item.name));
    const manifest = JSON.parse(readFileSync(join(unpacked, 'community-' + platform + '.json'), 'utf8'));
    const envelope = JSON.parse(readFileSync(join(unpacked, 'community-' + platform + '-update.json'), 'utf8'));
    const payload = Buffer.from(envelope.payload, 'base64');
    const release = JSON.parse(payload);
    requireValue(artifact.length === item.size && digest(artifact) === item.sha256 &&
      manifest.version === '0.5.51' && manifest.artifact === item.name &&
      manifest.size === item.size && manifest.sha256 === item.sha256,
      'Community ' + platform + ' artifact verification failed');
    requireValue(verify(null, payload, key, Buffer.from(envelope.signature, 'base64')) &&
      release.version === '0.5.51' && release.edition === 'community' && release.platform === platform &&
      release.format === item.format && release.sha256 === item.sha256 && release.size === item.size &&
      Date.parse(release.expires_at) > Date.now(),
      'Community ' + platform + ' update signature or release has expired');
  }
  if (existsSync(target)) {
    requireValue(lstatSync(target).isDirectory() && !lstatSync(target).isSymbolicLink(),
      'Community installer directory is not a regular directory');
  } else mkdirSync(target, { recursive: true });
  for (const name of wanted.filter(name => name !== 'release-public-key.txt')) {
    const next = join(target, '.' + name + '.next');
    copyFileSync(join(unpacked, name), next);
    renameSync(next, join(target, name));
  }
  console.log('Verified Community agent 0.5.51 for Windows and Linux.');
} catch (error) {
  console.error('Error: ' + error.message);
  process.exitCode = 1;
} finally {
  if (stage) rmSync(stage, { recursive: true, force: true });
}
NODE
printf 'Fetching and verifying the private Community agents...\n'
printf '%s' "$registry_token" |
  run_docker run --rm -i --user "$(id -u):$(id -g)" \
    -v "$root:/work:z" -w /work \
    -e "MILVAGO_UPDATE_PUBLIC_KEY=$UPDATE_PUBLIC_KEY" \
    "$NODE_IMAGE" node .local/generated/fetch-agent-release.mjs ||
  fail 'The signed Community agent release could not be prepared. Check access to the private milvago-agent repository.'
unset registry_token
if (( docker_as_root )); then
  as_root chown "$(id -u):$(id -g)" "$auth_dir/config.json"
fi

printf 'Verifying the Community image signature...\n'
run_docker run --rm --user "$(id -u):$(id -g)" -e HOME=/tmp \
  -v "$auth_dir:/docker-config:ro,Z" \
  -v "$root/cosign.pub:/cosign.pub:ro,z" \
  -e DOCKER_CONFIG=/docker-config \
  "$COSIGN_IMAGE" verify --key /cosign.pub --insecure-ignore-tlog=true "$IMAGE" >/dev/null ||
  fail 'The image signature could not be verified.'

if [[ ! -e "$root/.env" ]]; then
  printf 'Generating local configuration...\n'
  run_docker run --rm --network none --user "$(id -u):$(id -g)" \
    -v "$root:/work:z" -w /work \
    "$NODE_IMAGE" node scripts/local-init.mjs
fi

# Existing configurations may predate the first-run setup token.
run_docker run --rm --network none --user 0 \
  -v "$root/.env:/run/milvago.env:rw,z" "$NODE_IMAGE" node -e '
const fs = require("node:fs");
const { randomBytes } = require("node:crypto");
const path = "/run/milvago.env";
const content = fs.readFileSync(path, "utf8");
const matches = [...content.matchAll(/^MILVAGO_SETUP_TOKEN=([^\r\n]*)/gm)];
if (matches.length > 1) throw new Error("Duplicate MILVAGO_SETUP_TOKEN entries in .env");
if (matches.length === 1 && matches[0][1]) {
  if (!/^[A-Za-z0-9_-]{32,}$/.test(matches[0][1])) {
    throw new Error("MILVAGO_SETUP_TOKEN is invalid in .env");
  }
} else {
  const token = randomBytes(32).toString("base64url");
  const updated = matches.length === 1
    ? content.replace(/^MILVAGO_SETUP_TOKEN=[^\r\n]*/m, "MILVAGO_SETUP_TOKEN=" + token)
    : content + (content.endsWith("\n") ? "" : "\n") + "MILVAGO_SETUP_TOKEN=" + token + "\n";
  fs.writeFileSync(path, updated);
  console.log("Generated the missing setup token in .env.");
}
fs.chmodSync(path, 0o600);
' || fail 'Cannot ensure MILVAGO_SETUP_TOKEN in .env.'

caddyfile="$root/.local/generated/Caddyfile.private"
cat > "$caddyfile" <<EOF
{
  admin off
  auto_https off
}
:8080 {
  @identity path /realms /realms/* /resources /resources/* /js /js/* /admin /admin/*
  handle @identity {
    reverse_proxy identity:8080 {
      header_up -Forwarded
      header_up Host $host_ip:4020
      header_up X-Forwarded-For {remote_host}
      header_up X-Forwarded-Host $host_ip:4020
      header_up X-Forwarded-Proto http
      header_up X-Forwarded-Port 4020
      header_up -X-Forwarded-Prefix
    }
  }
  handle {
    reverse_proxy application:4020
  }
}
EOF
chmod 0644 "$caddyfile"
override="$root/.local/generated/compose.private.yaml"
cat > "$override" <<EOF
services:
  database:
    volumes:
      - ./deploy/postgres-init.sh:/docker-entrypoint-initdb.d/10-milvago.sh:ro,z
  identity:
    environment:
      KC_HOSTNAME: http://$host_ip:4020
      KC_PROXY_HEADERS: xforwarded
    ports: !override []
    volumes:
      - ${MILVAGO_REALM_FILE:-./.local/generated/realm.json}:/opt/keycloak/data/import/milvago.json:ro,z
      - ./deploy/theme/milvago:/opt/keycloak/themes/milvago:ro,z
  application:
    build: !reset null
    image: $IMAGE
    environment:
      APP_URL: http://$host_ip:4020
      OIDC_ISSUER: http://$host_ip:4020/realms/milvago
      MILVAGO_INSTALLER_DIRECTORY: /installers
      MILVAGO_UPDATE_PUBLIC_KEY: $UPDATE_PUBLIC_KEY
    ports: !override []
    volumes:
      - ./.local/installers:/installers:ro,z
  gateway:
    image: $CADDY_IMAGE
    user: "65532:65532"
    read_only: true
    tmpfs:
      - /data:uid=65532,gid=65532
      - /config:uid=65532,gid=65532
    cap_drop: [ALL]
    cap_add: [NET_BIND_SERVICE]
    ports:
      - "$host_ip:4020:8080"
    volumes:
      - ./.local/generated/Caddyfile.private:/etc/caddy/Caddyfile:ro,z
    depends_on:
      - identity
      - application
EOF

cd "$root"
compose=(compose -f compose.yaml -f "$override")
realm_file=${MILVAGO_REALM_FILE:-$root/.local/generated/realm.json}
if [[ "$realm_file" != /* ]]; then realm_file="$root/${realm_file#./}"; fi
[[ -f "$realm_file" && ! -L "$realm_file" ]] || fail 'The Keycloak realm file is missing or is a symlink.'
# Keycloak runs as uid 1000 with gid 0. The realm contains client secrets, so
# grant its container group read access without making it world-readable.
run_docker run --rm --network none --user 0 \
  -v "$realm_file:/run/milvago-realm.json:rw,z" "$NODE_IMAGE" node -e '
const fs = require("node:fs");
const path = "/run/milvago-realm.json";
const { uid } = fs.statSync(path);
fs.chownSync(path, uid, 0);
fs.chmodSync(path, 0o640);
' || fail 'Cannot grant Keycloak read access to realm.json.'
run_docker "${compose[@]}" config --quiet || fail 'The private-image Compose configuration is invalid.'
printf 'Pulling the verified image and starting Community...\n'
run_docker "${compose[@]}" pull application gateway
run_docker "${compose[@]}" up -d database identity
identity_id=$(run_docker "${compose[@]}" ps -q identity)
[[ -n "$identity_id" ]] || fail 'The identity container did not start.'
printf 'Configuring Keycloak redirects and password recovery for http://%s:4020...\n' "$host_ip"
run_docker run --rm --network "container:$identity_id" --user "$(id -u):$(id -g)" \
  -v "$root/.env:/run/milvago.env:ro,z" -e "MILVAGO_APP_URL=http://$host_ip:4020" \
  "$NODE_IMAGE" node -e '
(async () => {
  const fs = require("node:fs");
  const line = fs.readFileSync("/run/milvago.env", "utf8").split(/\r?\n/)
    .find((entry) => entry.startsWith("IDENTITY_ADMIN_PASSWORD="));
  const password = line?.slice("IDENTITY_ADMIN_PASSWORD=".length);
  if (!password) throw new Error("IDENTITY_ADMIN_PASSWORD is missing from .env");
  const base = "http://127.0.0.1:8080";
  const form = new URLSearchParams({
    grant_type: "password",
    client_id: "admin-cli",
    username: "bootstrap-admin",
    password,
  });
  let tokenResponse;
  let lastStatus = "unreachable";
  for (let attempt = 0; attempt < 60; attempt++) {
    try {
      tokenResponse = await fetch(base + "/realms/master/protocol/openid-connect/token", {
        method: "POST",
        body: form,
      });
      if (tokenResponse.ok) break;
      lastStatus = "HTTP " + tokenResponse.status;
      if (tokenResponse.status === 400 || tokenResponse.status === 401) {
        const response = await tokenResponse.json().catch(() => ({}));
        throw new Error("Keycloak administrator login rejected (" + lastStatus +
          (typeof response.error === "string" ? ", " + response.error : "") + ")");
      }
    } catch (error) {
      if (error.message.startsWith("Keycloak administrator login rejected")) throw error;
    }
    await new Promise((resolve) => setTimeout(resolve, 1000));
  }
  if (!tokenResponse?.ok) throw new Error("Keycloak did not become ready (" + lastStatus +
    "). Check the identity container logs.");
  const accessToken = (await tokenResponse.json()).access_token;
  const headers = { Authorization: "Bearer " + accessToken, Accept: "application/json" };
  const clientsResponse = await fetch(base + "/admin/realms/milvago/clients?clientId=milvago-console", { headers });
  if (!clientsResponse.ok) throw new Error("Keycloak client lookup returned HTTP " + clientsResponse.status);
  const clients = await clientsResponse.json();
  const client = clients.find((entry) => entry.clientId === "milvago-console");
  if (!client?.id) throw new Error("The Milvago console client is missing");
  const appURL = process.env.MILVAGO_APP_URL;
  client.redirectUris = [appURL + "/auth/callback"];
  client.webOrigins = [appURL];
  client.attributes = { ...client.attributes, "post.logout.redirect.uris": appURL + "/*" };
  const update = await fetch(base + "/admin/realms/milvago/clients/" + encodeURIComponent(client.id), {
    method: "PUT",
    headers: { ...headers, "Content-Type": "application/json" },
    body: JSON.stringify(client),
  });
  if (!update.ok) throw new Error("Keycloak client update returned HTTP " + update.status);
  const realmResponse = await fetch(base + "/admin/realms/milvago", { headers });
  if (!realmResponse.ok) throw new Error("Keycloak realm lookup returned HTTP " + realmResponse.status);
  const realm = await realmResponse.json();
  const resetPath = base + "/admin/realms/milvago/authentication/flows/" +
    encodeURIComponent(realm.resetCredentialsFlow || "reset credentials") + "/executions";
  const readReset = async () => {
    const response = await fetch(resetPath, { headers });
    if (!response.ok) throw new Error("Keycloak password reset flow lookup returned HTTP " + response.status);
    return response.json();
  };
  const otpReset = (await readReset()).find((entry) => entry.displayName === "Reset - Conditional OTP");
  if (!otpReset?.id) throw new Error("Keycloak password reset OTP step is missing");
  if (otpReset.requirement !== "DISABLED") {
    const change = await fetch(resetPath, {
      method: "PUT",
      headers: { ...headers, "Content-Type": "application/json" },
      body: JSON.stringify({ id: otpReset.id, requirement: "DISABLED" }),
    });
    if (!change.ok) throw new Error("Keycloak password reset OTP change returned HTTP " + change.status);
  }
  const applied = (await readReset()).find((entry) => entry.id === otpReset.id);
  if (applied?.requirement !== "DISABLED") throw new Error("Keycloak password reset OTP change was not applied");
})().catch((error) => {
  console.error("Error: " + error.message);
  process.exitCode = 1;
});
' || fail 'Keycloak could not be configured for the LAN address and password-only recovery.'
run_docker "${compose[@]}" up -d --no-build
gateway_id=$(run_docker "${compose[@]}" ps -q gateway)
if [[ -z "$gateway_id" ]]; then
  run_docker "${compose[@]}" logs --tail 40 gateway >&2 || true
  fail 'The Caddy gateway did not start.'
fi
printf 'Waiting for the Community gateway to become ready...\n'
if ! run_docker run --rm --network host -e "MILVAGO_APP_URL=http://$host_ip:4020" "$NODE_IMAGE" node -e '
(async () => {
  for (let attempt = 0; attempt < 45; attempt++) {
    try {
      const response = await fetch(process.env.MILVAGO_APP_URL + "/readyz", {
        signal: AbortSignal.timeout(2000),
      });
      if (response.status === 200) return;
    } catch {}
    await new Promise((resolve) => setTimeout(resolve, 1000));
  }
  throw new Error("Community did not become ready at the LAN address");
})().catch((error) => {
  console.error("Error: " + error.message);
  process.exitCode = 1;
});
' ; then
  run_docker "${compose[@]}" ps >&2 || true
  run_docker "${compose[@]}" logs --tail 40 gateway >&2 || true
  fail 'The Community gateway did not become ready. Check the application container logs.'
fi
printf '\nOpen http://%s:4020 for initial setup.\n' "$host_ip"
printf 'Find the setup token and generated secrets in %s/.env (owner-only).\n' "$root"
printf 'If the page is unreachable, allow TCP port 4020 through the host firewall.\n'
