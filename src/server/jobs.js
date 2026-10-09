import { Worker } from 'node:worker_threads';
import { availableParallelism } from 'node:os';
import { AnalysisError } from '../core/errors.js';

export const MAX_CONCURRENCY = Math.max(1, Math.min(4, availableParallelism()));

// Options are trusted embedding/test configuration, never request parameters.
export function createJobRunner({ maximum = MAX_CONCURRENCY, timeoutMs = 30000, workerURL = new URL('./job-worker.js', import.meta.url) } = {}) {
  if (!Number.isInteger(maximum) || maximum < 1 || !Number.isFinite(timeoutMs) || timeoutMs <= 0) throw new TypeError('invalid-job-limits');
  let active = 0;
  return function runJob(operation, bytes, options = {}) {
    if (active >= maximum) return Promise.reject(new AnalysisError('busy'));
    active++;
    return new Promise((resolve, reject) => {
      let worker, timer, settled = false;
      const finish = async (error, result) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        // Release the slot only after the timed-out/finished thread has stopped.
        try { await worker?.terminate(); } catch { error ||= new AnalysisError('worker-failed'); }
        active--;
        if (error) reject(error); else resolve(result);
      };
      try {
        worker = new Worker(workerURL, {
          workerData: { operation, bytes, options }, transferList: [bytes.buffer], resourceLimits: { maxOldGenerationSizeMb: 256 },
          stdout: true, stderr: true,
        });
        // Worker diagnostics must never corrupt the MCP JSON-RPC stdout stream.
        worker.stdout.pipe(process.stderr, { end: false });
        worker.stderr.pipe(process.stderr, { end: false });
        timer = setTimeout(() => void finish(new AnalysisError('timeout')), timeoutMs);
        worker.once('message', message => {
          if (message?.ok === true && message.result && typeof message.result === 'object') void finish(null, message.result);
          else if (message?.ok === false && typeof message.error?.code === 'string') void finish(new AnalysisError(message.error.code, message.error.details));
          else void finish(new AnalysisError('worker-failed'));
        });
        worker.once('error', () => void finish(new AnalysisError('worker-failed')));
        worker.once('exit', () => { if (!settled) void finish(new AnalysisError('worker-failed')); });
      } catch { void finish(new AnalysisError('worker-failed')); }
    });
  };
}

export const runJob = createJobRunner();
