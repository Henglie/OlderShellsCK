// FSG aPLib-style stream, adapted from XStaticUnpacker xfsg.cpp (MIT).
// Copyright (c) 2017-2026 hors<horsicq@gmail.com>
// Revision 746fb24433c29b6460edebac83fdad19909d9e81.
// See licenses/xstaticunpacker-MIT.txt and docs/research/fsg-implementation.md.
import { MAX_INPUT, MAX_OUTPUT } from '../bytes.js';
import { requireThat } from '../errors.js';

// Each stream starts with one literal and ends with 110 + distance byte 0/1.
// The consumed count includes tag bytes and the terminator, not trailing data.
export function decompressFsg(input, maxOutput) {
  requireThat(input instanceof Uint8Array, 'invalid-input');
  requireThat(input.length <= MAX_INPUT, 'input-size-limit');
  requireThat(Number.isInteger(maxOutput) && maxOutput >= 0 && maxOutput <= MAX_OUTPUT, 'invalid-output-limit');
  let source = 0, written = 0, tag = 0, bits = 0, previous = 0, literalState = 1;
  // Grow with actual output, not with untrusted declared virtual capacity.
  let output = new Uint8Array(Math.min(maxOutput, 4096));
  const byte = () => {
    requireThat(source < input.length, 'truncated-input');
    return input[source++];
  };
  const bit = () => {
    if (bits === 0) { tag = byte(); bits = 8; }
    const value = tag >>> 7;
    tag = (tag << 1) & 255; bits--;
    return value;
  };
  const gamma = () => {
    let value = 1;
    do {
      value = value * 2 + bit();
      // No valid output distance/length needs more than 28 value bits.
      requireThat(value <= MAX_OUTPUT + 2, 'fsg-integer-overflow');
    } while (bit());
    return value;
  };
  const reserve = size => {
    requireThat(size <= maxOutput - written, 'output-limit');
    const needed = written + size;
    if (needed > output.length) {
      const next = new Uint8Array(Math.min(maxOutput, Math.max(needed, output.length * 2)));
      next.set(output); output = next;
    }
  };
  const literal = value => { reserve(1); output[written++] = value; };
  literal(byte());
  // Every non-terminal token emits >=1 byte, so iterations <= maxOutput+1.
  for (let tokens = 0; tokens <= maxOutput; tokens++) {
    if (!bit()) { literal(byte()); literalState = 1; continue; }
    let distance, length;
    if (!bit()) {
      const high = gamma() - 1 - literalState;
      if (high === 0) { distance = previous; length = gamma(); }
      else {
        distance = (high - 1) * 256 + byte();
        length = gamma();
        if (distance >= 0x7d00) length++;
        if (distance >= 0x500) length++;
        if (distance <= 0x7f) length += 2;
        previous = distance;
      }
      literalState = 0;
    } else if (!bit()) {
      const value = byte();
      distance = value >>> 1;
      if (distance === 0) return { bytes: output.slice(0, written), consumed: source };
      length = 2 + (value & 1); previous = distance; literalState = 0;
    } else {
      distance = 0;
      for (let i = 0; i < 4; i++) distance = distance * 2 + bit();
      literalState = 1;
      if (distance === 0) { literal(0); continue; }
      length = 1;
    }
    requireThat(distance > 0 && distance <= written, 'invalid-back-reference');
    reserve(length);
    // Bytewise copy intentionally permits overlapping LZ matches.
    for (let i = 0; i < length; i++, written++) output[written] = output[written - distance];
  }
  requireThat(false, 'output-limit');
}
