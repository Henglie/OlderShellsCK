export class WorkerPool {
  constructor() { this.maximum = Math.max(1, Math.min(4, navigator.hardwareConcurrency || 2)); this.active = new Set(); this.queue = []; }
  run(file, operation, options, onStart) {
    return new Promise((resolve, reject) => { this.queue.push({ file, operation, options, onStart, resolve, reject }); this.drain(); });
  }
  drain() {
    while (this.active.size < this.maximum && this.queue.length) {
      const job = this.queue.shift(); this.active.add(job); job.onStart?.();
      this.start(job);
    }
  }
  async start(job) {
    let worker;
    const finish = (error, result) => {
      if (!this.active.delete(job)) return;
      clearTimeout(job.timer); worker?.terminate();
      error ? job.reject(error) : job.resolve(result);
      this.drain();
    };
    job.cancel = () => finish({ code: 'cancelled' });
    job.timer = setTimeout(() => finish({ code: 'timeout' }), 30000);
    try {
      const buffer = await job.file.arrayBuffer();
      if (!this.active.has(job)) return;
      worker = new Worker(new URL('./worker.js', import.meta.url), { type: 'module' });
      worker.onmessage = ({ data }) => data.ok ? finish(null, data.result) : finish(data.error);
      worker.onerror = () => finish({ code: 'worker-failed' });
      worker.postMessage({ buffer, operation: job.operation, options: job.options }, [buffer]);
    } catch { finish({ code: 'worker-failed' }); }
  }
  cancel() {
    for (const job of this.queue.splice(0)) job.reject({ code: 'cancelled' });
    for (const job of [...this.active]) job.cancel();
  }
}
