import { execute } from '../core/index.js';
import { serializeError } from '../core/errors.js';
self.onmessage = async ({ data }) => {
  try {
    const result = await execute(data.operation, new Uint8Array(data.buffer), data.options);
    self.postMessage({ ok: true, result }, result.bytes ? [result.bytes.buffer] : []);
  } catch (error) { self.postMessage({ ok: false, error: serializeError(error) }); }
};
