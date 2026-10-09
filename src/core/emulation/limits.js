import { MAX_INPUT, MAX_OUTPUT } from '../bytes.js';
import { requireThat } from '../errors.js';

// Immutable policy; every execution gets its own validated budget object.
const DEFAULTS = Object.freeze({
  maxInput: MAX_INPUT, maxOutput: MAX_OUTPUT, maxMemory: 128 * 1024 * 1024,
  stackSize: 1024 * 1024, maxSteps: 10000000, maxWriteBytes: 256 * 1024 * 1024,
  maxApiEntries: 4096, maxApiCalls: 16384,
});
const CEILINGS = Object.freeze({
  maxInput: MAX_INPUT, maxOutput: MAX_OUTPUT, maxMemory: 256 * 1024 * 1024,
  stackSize: 8 * 1024 * 1024, maxSteps: 100000000, maxWriteBytes: 1024 * 1024 * 1024,
  maxApiEntries: 16384, maxApiCalls: 65536,
});

export function emulationLimits(options = {}) {
  requireThat(options && typeof options === 'object' && !Array.isArray(options), 'invalid-emulation-options');
  const result = {};
  for (const key of Object.keys(DEFAULTS)) {
    const value = options[key] === undefined ? DEFAULTS[key] : options[key];
    requireThat(Number.isSafeInteger(value) && value > 0 && value <= CEILINGS[key],
      'invalid-emulation-budget', { budget: key, max: CEILINGS[key] });
    result[key] = value;
  }
  requireThat(result.stackSize >= 256 && result.stackSize % 16 === 0,
    'invalid-emulation-budget', { budget: 'stackSize' });
  return Object.freeze(result);
}
