let compiled: Promise<WebAssembly.Module> | undefined;

type Exports = { memory: WebAssembly.Memory; dlp_alloc: (size: number) => number; dlp_call: (pointer: number, size: number) => bigint; dlp_free: (pointer: number, size: number) => void };

self.onmessage = async (event: MessageEvent<{ id: number; request: unknown }>) => {
  const { id, request } = event.data;
  try {
    compiled ??= fetch('/dlp_engine.wasm', { credentials: 'same-origin', cache: 'no-store' }).then(response => {
      if (!response.ok) throw new Error('DLP engine unavailable');
      return response.arrayBuffer();
    }).then(bytes => WebAssembly.compile(bytes)).catch(error=>{compiled=undefined;throw error;});
    const instance = await WebAssembly.instantiate(await compiled, {});
    const exports = instance.exports as unknown as Exports;
    const input = new TextEncoder().encode(JSON.stringify(request));
    if (input.length > 524288) throw new Error('DLP input exceeds the limit');
    const address = exports.dlp_alloc(input.length);
    if (!address) throw new Error('DLP allocation failed');
    new Uint8Array(exports.memory.buffer, address, input.length).set(input);
    const packed = exports.dlp_call(address, input.length);
    const pointer = Number(packed & 0xffffffffn);
    const length = Number(packed >> 32n);
    if (!pointer || !length || length > 1048576) throw new Error('DLP result exceeds the limit');
    const output = new TextDecoder('utf-8', { fatal: true }).decode(new Uint8Array(exports.memory.buffer, pointer, length));
    exports.dlp_free(pointer, length);
    self.postMessage({ id, response: JSON.parse(output) });
  } catch {
    self.postMessage({ id, response: { ok: false, error: 'DLP engine unavailable' } });
  }
};
