import { parentPort, workerData } from 'node:worker_threads';
import { unpackEmulated } from '../../src/core/unpackers/emulated.js';

try {
  const result = unpackEmulated(new Uint8Array(workerData.bytes), workerData.name, workerData.options ?? {});
  parentPort.postMessage({ result });
} catch (error) {
  parentPort.postMessage({ error: { name: error.name, code: error.code, details: error.details } });
}
