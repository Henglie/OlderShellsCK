import { MAX_INPUT, MAX_OUTPUT } from '../core/bytes.js';
import { requireThat } from '../core/errors.js';
export const MAX_BASE64 = Math.ceil(MAX_INPUT / 3) * 4;
export const MAX_JSON = MAX_BASE64 + 4096;
export const UNPACK_MODES = Object.freeze(['auto-oep', 'extract']);
// Armadillo oracle knobs (MT30): mirrors the constraints enforced by
// unpackArmadillo so bad input fails at the transport with a stable code.
const PROBE_SIZES = Object.freeze([2, 5, 6]);
const u32 = value => Number.isInteger(value) && value >= 0 && value <= 0xffffffff;
const validSamples = samples => Array.isArray(samples) && samples.length > 0 && samples.length <= 128;
const validProbes = (probes, requireSamples) => Array.isArray(probes) && probes.length > 0 && probes.length <= 32
  && probes.every(probe => probe && typeof probe === 'object' && !Array.isArray(probe) && u32(probe.address)
    && PROBE_SIZES.includes(probe.size)
    && (requireSamples ? validSamples(probe.samples) : (probe.samples === undefined || validSamples(probe.samples))));
const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
const values = new Uint8Array(128).fill(255);
for (let i = 0; i < alphabet.length; i++) values[alphabet.charCodeAt(i)] = i;

export function decodeRequest(body) {
  requireThat(body && typeof body === 'object' && !Array.isArray(body), 'invalid-request');
  const encoded = body.dataBase64;
  requireThat(typeof encoded === 'string' && encoded.length > 0 && encoded.length <= MAX_BASE64, 'input-size-limit');
  requireThat(encoded.length % 4 === 0, 'invalid-base64');
  requireThat(body.name === undefined || (typeof body.name === 'string' && body.name.length <= 256), 'invalid-name');
  requireThat(body.engine === undefined || typeof body.engine === 'string', 'unknown-engine');
  requireThat(body.mode === undefined || UNPACK_MODES.includes(body.mode), 'invalid-mode');
  requireThat(body.oepRva === undefined || (Number.isInteger(body.oepRva) && body.oepRva > 0 && body.oepRva <= 0xFFFFFFF), 'invalid-oep-rva');
  requireThat(body.timeoutSeconds === undefined || (Number.isFinite(body.timeoutSeconds) && body.timeoutSeconds >= 0.1 && body.timeoutSeconds <= 60), 'invalid-timeout-seconds');
  requireThat(body.maxEvents === undefined || (Number.isInteger(body.maxEvents) && body.maxEvents >= 16 && body.maxEvents <= 50000), 'invalid-max-events');
  requireThat(body.sampleArgs === undefined || (Array.isArray(body.sampleArgs) && body.sampleArgs.length <= 32
    && body.sampleArgs.every(arg => typeof arg === 'string' && arg.length <= 4096 && !arg.includes('\0'))), 'invalid-sample-args');
  requireThat(body.imageBase === undefined || u32(body.imageBase), 'invalid-image-base');
  if (body.probes !== undefined) requireThat(validProbes(body.probes, false), 'invalid-probe-plan');
  if (body.probePlan !== undefined) {
    const plan = body.probePlan;
    requireThat(plan && typeof plan === 'object' && !Array.isArray(plan) && u32(plan.imageBase)
      && validProbes(plan.probes, true)
      && plan.probes.every(probe => probe.address >= plan.imageBase), 'invalid-probe-plan');
  }
  const padding = encoded.endsWith('==') ? 2 : encoded.endsWith('=') ? 1 : 0;
  const end = encoded.length - padding;
  requireThat(encoded.length / 4 * 3 - padding <= MAX_INPUT, 'input-size-limit');
  // One linear scan, constant stack, no decode/re-encode copy of a 64 MiB file.
  for (let i = 0; i < end; i++) {
    const code = encoded.charCodeAt(i);
    requireThat(code < 128 && values[code] !== 255, 'invalid-base64');
  }
  // RFC 4648: the unused low bits in the final sextet must be zero.
  requireThat(!padding || (values[encoded.charCodeAt(end - 1)] & (padding === 2 ? 15 : 3)) === 0, 'invalid-base64');
  const data = Buffer.from(encoded, 'base64');
  return {
    bytes: new Uint8Array(data),
    options: {
      name: body.name, engine: body.engine, oepRva: body.oepRva, mode: body.mode,
      ...(body.probes !== undefined && { probes: body.probes }),
      ...(body.probePlan !== undefined && { probePlan: body.probePlan }),
      ...(body.timeoutSeconds !== undefined && { timeoutSeconds: body.timeoutSeconds }),
      ...(body.maxEvents !== undefined && { maxEvents: body.maxEvents }),
      ...(body.sampleArgs !== undefined && { sampleArgs: body.sampleArgs }),
      ...(body.imageBase !== undefined && { imageBase: body.imageBase }),
    },
  };
}

export function encodeResult(result) {
  if (!result.bytes) return result;
  const { bytes, ...rest } = result;
  requireThat(bytes instanceof Uint8Array && bytes.length <= MAX_OUTPUT, 'output-size-limit');
  return { ...rest, dataBase64: Buffer.from(bytes.buffer, bytes.byteOffset, bytes.byteLength).toString('base64') };
}
