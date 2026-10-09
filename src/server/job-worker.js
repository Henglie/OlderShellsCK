import { parentPort, workerData } from 'node:worker_threads';
import { execute } from '../core/index.js';
import './engines-server.js';
import { serializeError } from '../core/errors.js';
try {
  const result = await execute(workerData.operation, workerData.bytes, workerData.options);
  parentPort.postMessage({ ok: true, result }, result.bytes ? [result.bytes.buffer] : []);
} catch (error) { parentPort.postMessage({ ok: false, error: serializeError(error) }); }
