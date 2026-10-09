// Bounded raw LZMA1 decoder; independent JS transcription of the LZMA model.
// Format/reference: Igor Pavlov, LZMA SDK LzmaDec.c (2023-04-07), public domain.
// https://raw.githubusercontent.com/ip7z/7zip/24.09/C/LzmaDec.c
// No SDK source or unknown-license decompilation is embedded here.
// This file's original implementation is SPDX-License-Identifier: Apache-2.0.
import { MAX_INPUT, MAX_OUTPUT } from '../bytes.js';
import { requireThat } from '../errors.js';

// A raw stream has a 5-byte range initializer, no .xz/.lzma container header.
// Exact output length is mandatory. EOS or code==0 validates the final state;
// reaching the requested length alone is not success (nor is implicit padding).
export function decodeLzma1(input, outputSize, { props = 0x5d, dictionarySize = 0x100000 } = {}) {
  requireThat(input instanceof Uint8Array, 'invalid-input');
  requireThat(input.length <= MAX_INPUT, 'input-size-limit');
  requireThat(Number.isInteger(outputSize) && outputSize >= 0 && outputSize <= MAX_OUTPUT, 'invalid-output-limit');
  requireThat(Number.isInteger(props) && props >= 0 && props < 225, 'invalid-lzma-properties');
  const lc = props % 9, lp = Math.floor(props / 9) % 5, pb = Math.floor(props / 45);
  // Bounded model subset, also accepted by liblzma: includes MEW lc4/lp0/pb2.
  requireThat(lc + lp <= 4, 'unsupported-lzma-properties');
  requireThat(Number.isInteger(dictionarySize) && dictionarySize >= 0x1000 && dictionarySize <= MAX_OUTPUT, 'invalid-lzma-dictionary');
  let source = 0, range = 0xffffffff, code = 0, written = 0, state = 0;
  const read = () => { requireThat(source < input.length, 'truncated-input'); return input[source++]; };
  requireThat(read() === 0, 'invalid-lzma-stream');
  for (let i = 0; i < 4; i++) code = (code * 256 + read()) >>> 0;
  requireThat(code < range, 'invalid-lzma-stream');
  const normalize = () => {
    if (range < 0x1000000) { range = (range * 256) >>> 0; code = (code * 256 + read()) >>> 0; }
    requireThat(range > 0 && code < range, 'invalid-lzma-stream');
  };
  const model = n => new Uint16Array(n).fill(1024);
  const isMatch = model(12 * 16), isRep = model(12), g0 = model(12), g1 = model(12), g2 = model(12);
  const rep0Long = model(12 * 16), slots = model(4 * 64), distances = model(128), alignment = model(16);
  const literalModel = model(0x300 * 2 ** (lc + lp));
  const lenModel = () => ({ choice: model(2), low: model(16 * 8), mid: model(16 * 8), high: model(256) });
  const lengths = lenModel(), repLengths = lenModel();
  const bit = (p, i) => {
    normalize();
    const probability = p[i], bound = (range >>> 11) * probability;
    requireThat(probability > 0 && probability < 2048, 'invalid-lzma-model');
    if (code < bound) { range = bound; p[i] += (2048 - probability) >>> 5; return 0; }
    range -= bound; code -= bound; p[i] -= probability >>> 5; return 1;
  };
  const tree = (p, start, bits, reverse = false) => {
    let node = 1, value = 0;
    for (let i = 0; i < bits; i++) { const b = bit(p, start + node); node = node * 2 + b; value += b * 2 ** i; }
    return reverse ? value : node - 2 ** bits;
  };
  const length = (p, pos) => {
    if (!bit(p.choice, 0)) return tree(p.low, pos * 8, 3) + 2;
    if (!bit(p.choice, 1)) return tree(p.mid, pos * 8, 3) + 10;
    return tree(p.high, 0, 8) + 18;
  };
  const direct = bits => {
    let value = 0;
    for (let i = 0; i < bits; i++) {
      normalize(); range = Math.floor(range / 2); value *= 2;
      if (code >= range) { code -= range; value++; }
    }
    return value;
  };
  const output = new Uint8Array(outputSize), reps = [1, 1, 1, 1];
  const back = (distance, count) => {
    requireThat(distance > 0 && distance <= written && distance <= dictionarySize, 'invalid-back-reference');
    requireThat(count <= outputSize - written, 'decoded-size-mismatch');
    for (let i = 0; i < count; i++, written++) output[written] = output[written - distance];
  };
  const posMask = 2 ** pb - 1, literalMask = 2 ** lp - 1;
  // Every ordinary symbol produces >=1 byte. One additional symbol may be EOS.
  for (let tokens = 0; tokens <= outputSize; tokens++) {
    if (written === outputSize) {
      normalize();
      if (code === 0) return { bytes: output, consumed: source, endMarker: false };
    }
    const pos = written & posMask;
    if (!bit(isMatch, state * 16 + pos)) {
      requireThat(written < outputSize, 'decoded-size-mismatch');
      const previous = written ? output[written - 1] : 0;
      const context = ((written & literalMask) * 2 ** lc + (previous >>> (8 - lc))) * 0x300;
      let symbol = 1;
      if (state >= 7) {
        requireThat(reps[0] <= written && reps[0] <= dictionarySize, 'invalid-back-reference');
        let matched = output[written - reps[0]];
        do {
          const expected = matched >>> 7; matched = (matched * 2) & 255;
          const b = bit(literalModel, context + (1 + expected) * 256 + symbol);
          symbol = symbol * 2 + b;
          if (b !== expected) break;
        } while (symbol < 256);
      }
      while (symbol < 256) symbol = symbol * 2 + bit(literalModel, context + symbol);
      output[written++] = symbol & 255;
      state = state < 4 ? 0 : state < 10 ? state - 3 : state - 6;
      continue;
    }
    let count;
    if (bit(isRep, state)) {
      requireThat(written < outputSize, 'decoded-size-mismatch');
      if (!bit(g0, state)) {
        if (!bit(rep0Long, state * 16 + pos)) { back(reps[0], 1); state = state < 7 ? 9 : 11; continue; }
      } else {
        let index;
        if (!bit(g1, state)) index = 1;
        else index = !bit(g2, state) ? 2 : 3;
        const distance = reps[index];
        for (let i = index; i > 0; i--) reps[i] = reps[i - 1];
        reps[0] = distance;
      }
      count = length(repLengths, pos); state = state < 7 ? 8 : 11;
    } else {
      count = length(lengths, pos);
      const slot = tree(slots, Math.min(count - 2, 3) * 64, 6);
      let distance = slot;
      if (slot >= 4) {
        const extra = Math.floor(slot / 2) - 1;
        distance = (2 + (slot & 1)) * 2 ** extra;
        if (slot < 14) distance += tree(distances, distance - slot - 1, extra, true);
        else distance += direct(extra - 4) * 16 + tree(alignment, 0, 4, true);
      }
      if (distance === 0xffffffff) {
        requireThat(written === outputSize, 'decoded-size-mismatch');
        normalize(); requireThat(code === 0, 'invalid-lzma-stream');
        return { bytes: output, consumed: source, endMarker: true };
      }
      reps[3] = reps[2]; reps[2] = reps[1]; reps[1] = reps[0]; reps[0] = distance + 1;
      state = state < 7 ? 7 : 10;
    }
    back(reps[0], count);
  }
  requireThat(false, 'invalid-lzma-stream');
}
