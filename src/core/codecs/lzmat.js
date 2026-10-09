/**
 * @file src/unpacker/decompression/lzmat/lzmat_data.cpp
 * @brief Implementation of class for compressed LZMAT data representation.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 *
 * Bounded JavaScript port of RetDec's LzmatData::decompress at commit
 * 9450585772e6f1c18e5f0b2ad5518a18d6bce71e:
 * https://github.com/avast/retdec/blob/9450585772e6f1c18e5f0b2ad5518a18d6bce71e/src/unpacker/decompression/lzmat/lzmat_data.cpp
 * License: licenses/retdec-MIT.txt in the repository root.
 * SPDX-License-Identifier: MIT
 */

import { AnalysisError } from '../errors.js';

const MAX_BYTES = 128 * 1024 * 1024;

/**
 * Decode one raw LZMAT stream, including its first verbatim byte.
 * maxOutput is a capacity ceiling, not an expected decompressed size.
 * Like RetDec, stop when fewer than eight input bits remain between tokens;
 * an unused final high nibble or a tag with no following token is accepted.
 * Consequently a stream cut at a token boundary cannot be detected here.
 * All distance modes and the 0xffff verbatim-block escape are supported.
 * No MPRESS header, LZMA properties, PE fixups, or zero padding are applied.
 *
 * @param {Uint8Array} input Exact compressed extent (no section padding).
 * @param {number} maxOutput Integer in [0, 128 MiB].
 * @returns {Uint8Array} An owned array containing only decoded bytes.
 * @throws {AnalysisError} With .code for invalid arguments, truncated tokens,
 * invalid back references, output overflow, or allocation failure.
 */
export function decompressLzmat(input, maxOutput) {
  if (!(input instanceof Uint8Array)) throw new AnalysisError('invalid-input');
  if (!Number.isSafeInteger(maxOutput) || maxOutput < 0 || maxOutput > MAX_BYTES) {
    throw new AnalysisError('invalid-output-limit', { maxOutput, limit: MAX_BYTES });
  }
  if (input.length > MAX_BYTES) throw new AnalysisError('input-too-large', { limit: MAX_BYTES });

  let cursor = 0; // Nibble offset: low nibble first, then high nibble.
  let outputPos = 0;
  let output = new Uint8Array(0);

  function inputRange(offset, length) {
    if (offset < 0 || offset > input.length - length) {
      throw new AnalysisError('truncated-input', { offset, length });
    }
  }

  function read4() {
    const offset = Math.floor(cursor / 2);
    inputRange(offset, 1);
    const value = (input[offset] >>> ((cursor & 1) * 4)) & 0xf;
    cursor++;
    return value;
  }

  function read8() {
    const offset = Math.floor(cursor / 2);
    const unaligned = cursor & 1;
    inputRange(offset, 1 + unaligned);
    const value = unaligned
      ? (input[offset] >>> 4) | ((input[offset + 1] & 0xf) << 4)
      : input[offset];
    cursor += 2;
    return value;
  }

  function read16() {
    const low = read8();
    return low | (read8() << 8);
  }

  function reserve(length) {
    if (length > maxOutput - outputPos) {
      throw new AnalysisError('output-limit', { outputPos, length, maxOutput });
    }
    const needed = outputPos + length;
    if (needed <= output.length) return;
    const capacity = Math.min(maxOutput, Math.max(needed, 4096, output.length * 2));
    try {
      const grown = new Uint8Array(capacity);
      grown.set(output);
      output = grown;
    } catch {
      throw new AnalysisError('allocation-failed', { capacity });
    }
  }

  const first = read8();
  reserve(1);
  output[outputPos++] = first;

  while (cursor + 2 <= input.length * 2) {
    let tag = read8();
    for (let bit = 0; bit < 8 && cursor + 2 <= input.length * 2; bit++, tag = (tag << 1) & 0xff) {
      if (!(tag & 0x80)) {
        const literal = read8();
        reserve(1);
        output[outputPos++] = literal;
        continue;
      }

      // Consume only encoded distance bits, rather than RetDec's speculative
      // 32-bit load for get16Bits(). No zero-filled lookahead is required.
      const low = read8();
      let distance;
      if (outputPos < 0x881) {
        distance = low & 1
          ? (low >>> 1) + (read4() << 7) + 0x81
          : (low >>> 1) + 1;
      } else {
        switch (low & 3) {
          case 0: distance = (low >>> 2) + 1; break;
          case 1: distance = (low >>> 2) + (read4() << 6) + 0x41; break;
          case 2: distance = (low >>> 2) + (read8() << 6) + 0x441; break;
          case 3: distance = (low >>> 2) + (read8() << 6) + (read4() << 14) + 0x4441; break;
        }
      }

      let length = read4() + 3;
      if (length === 0x12) {
        length = read8() + 0x12;
        if (length === 0x111) {
          length = read16() + 0x111;
          if (length === 0x10110) {
            // Verbatim escape: its count reuses bits of the encoded distance
            // and the *shifted* tag. It also ends this tag's token group.
            let offset = Math.floor(cursor / 2);
            let count;
            if (cursor & 1) {
              inputRange(offset - 4, 1);
              count = (input[offset - 4] & 0xfc) << 5;
              offset++;
            } else {
              inputRange(offset - 5, 2);
              count = ((input[offset - 5] | (input[offset - 4] << 8)) & 0xfc0) << 1;
            }
            length = (count + (tag & 0x7f) + 4) * 8;
            inputRange(offset, length);
            reserve(length);
            output.set(input.subarray(offset, offset + length), outputPos);
            outputPos += length;
            cursor = (offset + length) * 2;
            break;
          }
        }
      }

      if (distance > outputPos) {
        throw new AnalysisError('invalid-back-reference', { outputPos, distance });
      }
      reserve(length);
      // Forward byte copying is essential: overlapping matches repeat newly
      // decoded bytes (TypedArray.copyWithin would use memmove semantics).
      const end = outputPos + length;
      while (outputPos < end) {
        output[outputPos] = output[outputPos - distance];
        outputPos++;
      }
    }
  }

  try {
    return output.slice(0, outputPos);
  } catch {
    throw new AnalysisError('allocation-failed', { capacity: outputPos });
  }
}
