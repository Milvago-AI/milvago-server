import { spawnSync } from 'node:child_process';
import { copyFileSync, mkdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { join } from 'node:path';

const root = fileURLToPath(new URL('../', import.meta.url));
const result = spawnSync('cargo', ['+1.96.1', 'build', '--release', '--locked', '--target', 'wasm32-unknown-unknown', '--manifest-path', join(root, 'dlp-engine', 'Cargo.toml')], { stdio: 'inherit' });
if (result.error || result.status !== 0) process.exit(result.status || 1);
for (const directory of ['server/internal/app', 'console/public']) {
  mkdirSync(join(root, directory), { recursive: true });
  copyFileSync(join(root, 'dlp-engine/target/wasm32-unknown-unknown/release/milvago_dlp_engine.wasm'), join(root, directory, 'dlp_engine.wasm'));
}
