export const WINDOWS_PACKAGE_PATH = '/api/installer/windows/package';
export const WINDOWS_PACKAGE_NAME = 'milvago-windows-package.zip';

export function saveBlob(blob: Blob, name: string) {
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = name;
  document.body.append(link);
  try { link.click(); } finally { link.remove(); window.setTimeout(() => URL.revokeObjectURL(url), 0); }
}
