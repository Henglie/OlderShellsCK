import { requireThat } from './errors.js';

export const MAX_INPUT = 64 * 1024 * 1024;
export const MAX_OUTPUT = 128 * 1024 * 1024;

export class Bytes {
  constructor(bytes) {
    requireThat(bytes instanceof Uint8Array, 'invalid-input');
    this.bytes = bytes;
    this.view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  }
  range(offset, length) {
    requireThat(Number.isSafeInteger(offset) && Number.isSafeInteger(length) && offset >= 0 && length >= 0 && offset <= this.bytes.length - length, 'truncated-input', { offset, length });
  }
  u8(offset) { this.range(offset, 1); return this.view.getUint8(offset); }
  u16(offset) { this.range(offset, 2); return this.view.getUint16(offset, true); }
  u32(offset) { this.range(offset, 4); return this.view.getUint32(offset, true); }
  i32(offset) { this.range(offset, 4); return this.view.getInt32(offset, true); }
  put32(offset, value) { this.range(offset, 4); this.view.setUint32(offset, value, true); }
  put16(offset, value) { this.range(offset, 2); this.view.setUint16(offset, value, true); }
  string(offset, length) {
    this.range(offset, length);
    let result = '';
    for (let i = offset; i < offset + length && this.bytes[i]; i++) result += String.fromCharCode(this.bytes[i]);
    return result;
  }
  cstring(offset, max = 512) {
    this.range(offset, 1);
    const end = Math.min(offset + max, this.bytes.length);
    let cursor = offset;
    while (cursor < end && this.bytes[cursor]) cursor++;
    requireThat(cursor < end, 'unterminated-string', { offset });
    return this.string(offset, cursor - offset);
  }
}

export function matchHex(bytes, offset, pattern) {
  if (!Number.isInteger(offset) || offset < 0 || !/^(?:[a-f\d]{2}|\.\.)+$/i.test(pattern)) return false;
  if (offset + pattern.length / 2 > bytes.length) return false;
  for (let i = 0; i < pattern.length; i += 2) {
    const pair = pattern.slice(i, i + 2);
    if (pair !== '..' && bytes[offset + i / 2] !== parseInt(pair, 16)) return false;
  }
  return true;
}

export function entropy(bytes) {
  if (!bytes.length) return 0;
  const bins = new Uint32Array(256);
  for (const value of bytes) bins[value]++;
  let value = 0;
  for (const count of bins) if (count) { const p = count / bytes.length; value -= p * Math.log2(p); }
  return Math.round(value * 1000) / 1000;
}

export function align(value, alignment) {
  requireThat(Number.isInteger(alignment) && alignment > 0 && alignment <= 65536 && (alignment & (alignment - 1)) === 0, 'invalid-alignment');
  return Math.ceil(value / alignment) * alignment;
}

export async function sha256(bytes) {
  const digest = await globalThis.crypto.subtle.digest('SHA-256', bytes);
  return Array.from(new Uint8Array(digest), b => b.toString(16).padStart(2, '0')).join('');
}
