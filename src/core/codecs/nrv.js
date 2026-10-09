// NRV2B/2D/2E adapted from RetDec, commit 9450585772e6f1c18e5f0b2ad5518a18d6bce71e.
// Copyright (c) 2017 Avast Software, licensed under MIT. See licenses/retdec-MIT.txt.
// Sources: src/unpacker/decompression/nrv/nrv2{b,d,e}_data.cpp.
import { MAX_INPUT, MAX_OUTPUT } from '../bytes.js';
import { requireThat } from '../errors.js';

/** Decode one NRV LE32 stream. Capacity is a bound, not an expected length.
 * Returns consumption so the container can reject trailing bytes. A real EOS is mandatory.
 * maxSteps counts bit reads, byte reads and output bytes; independent of wall-clock speed.
 */
export function decodeNrv(input, maxOutput, variant, options = {}) {
  requireThat(input instanceof Uint8Array, 'invalid-input');
  requireThat(input.length <= MAX_INPUT, 'input-size-limit');
  requireThat(Number.isInteger(maxOutput) && maxOutput >= 0 && maxOutput <= MAX_OUTPUT, 'invalid-output-limit');
  requireThat(['NRV2B', 'NRV2D', 'NRV2E'].includes(variant), 'unsupported-nrv-variant');
  requireThat(options !== null && typeof options === 'object', 'invalid-step-limit');
  const budget = Math.min(16 * (input.length + maxOutput) + 1024, 512 * 1024 * 1024);
  const maxSteps = options.maxSteps ?? budget;
  requireThat(Number.isSafeInteger(maxSteps) && maxSteps > 0 && maxSteps <= budget, 'invalid-step-limit');
  const output = new Uint8Array(maxOutput);
  let cursor = 0, written = 0, word = 0, bits = 0, steps = 0, lastDistance = 1;
  const tick = (count = 1) => { steps += count; requireThat(steps <= maxSteps, 'nrv-step-limit'); };
  const byte = () => {
    tick();
    requireThat(cursor < input.length, 'truncated-input');
    return input[cursor++];
  };
  const bit = () => {
    tick();
    if (!bits) {
      requireThat(cursor + 4 <= input.length, 'truncated-input');
      word = (input[cursor] | input[cursor + 1] << 8 | input[cursor + 2] << 16 | input[cursor + 3] << 24) >>> 0;
      cursor += 4;
      bits = 32;
    }
    const value = word >>> 31;
    word = (word << 1) >>> 0;
    bits--;
    return value;
  };
  const extendLength = () => {
    let value = 1;
    do {
      value = value * 2 + bit();
      requireThat(value <= maxOutput, 'output-limit');
    } while (!bit());
    return value;
  };
  for (;;) {
    while (bit()) {
      requireThat(written < maxOutput, 'output-limit');
      const value = byte();
      tick();
      output[written++] = value;
    }
    let prefix = 1;
    for (;;) {
      prefix = prefix * 2 + bit();
      // Largest prefix encodes the 0xffffffff EOS; no JS bitwise overflow allowed.
      requireThat(prefix <= 0x1000002, 'invalid-back-reference');
      if (bit()) break;
      if (variant !== 'NRV2B') {
        prefix = (prefix - 1) * 2 + bit();
        requireThat(prefix <= 0x1000002, 'invalid-back-reference');
      }
    }
    let distance, count;
    if (prefix === 2) {
      distance = lastDistance;
      if (variant !== 'NRV2B') count = bit();
    } else {
      const encoded = (prefix - 3) * 256 + byte();
      if (encoded === 0xffffffff) return { bytes: output.slice(0, written), bytesRead: cursor, steps };
      requireThat(encoded >= 0 && encoded < 0xffffffff, 'invalid-back-reference');
      if (variant === 'NRV2B') distance = encoded + 1;
      else { count = 1 - (encoded % 2); distance = Math.floor(encoded / 2) + 1; }
      lastDistance = distance;
    }
    requireThat(distance > 0 && distance <= written, 'invalid-back-reference');
    if (variant === 'NRV2E') {
      if (count) count = 1 + bit();
      else if (bit()) count = 3 + bit();
      else count = extendLength() + 3;
    } else {
      if (variant === 'NRV2B') count = bit();
      count = count * 2 + bit();
      if (!count) count = extendLength() + 2;
    }
    count += 1 + (distance > (variant === 'NRV2B' ? 0xd00 : 0x500) ? 1 : 0);
    requireThat(count <= maxOutput - written, 'output-limit');
    tick(count);
    // Deliberately forward-copy: short overlapping distances repeat previous output.
    for (let i = 0; i < count; i++) { output[written] = output[written - distance]; written++; }
  }
}

export function decompressNrv(input, maxOutput, variant, options) {
  return decodeNrv(input, maxOutput, variant, options).bytes;
}
