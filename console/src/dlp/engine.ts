type EngineResponse = { ok: boolean; error?: string; [key: string]: unknown };

// Workers never receive session credentials or send laboratory samples to the server.
export function createDlpEngine() {
  let worker: Worker | undefined;
  let sequence = 0;
  const pending = new Map<number, { resolve: (value: EngineResponse) => void; reject: (reason: Error) => void; timer: number }>();
  const close = () => {
    worker?.terminate(); worker = undefined;
    for (const item of pending.values()) { clearTimeout(item.timer); item.reject(new Error('DLP engine unavailable')); }
    pending.clear();
  };
  const call = (request: unknown): Promise<EngineResponse> => new Promise((resolve, reject) => {
    if (pending.size >= 8) { reject(new Error('DLP engine busy')); return; }
    if (!worker) {
      worker = new Worker(new URL('./engine.worker.ts', import.meta.url), { type: 'module' });
      worker.onmessage = (event: MessageEvent<{ id: number; response: EngineResponse }>) => {
        const item = pending.get(event.data.id); if (!item) return;
        pending.delete(event.data.id); clearTimeout(item.timer);
        if (event.data.response.ok) item.resolve(event.data.response); else item.reject(new Error(event.data.response.error || 'DLP input rejected'));
      };
      worker.onerror = close;
    }
    const id = ++sequence;
    const timer = window.setTimeout(close, 4000);
    pending.set(id, { resolve, reject, timer });
    worker.postMessage({ id, request });
  });
  return { call, close };
}
