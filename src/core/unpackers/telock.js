// tElock 0.9x wrapper layer transforms and payload codec grammar.
// Layer constants and decoder grammar are original findings of MT27/MT29/T41
// static analysis (docs/research/rlde-family.md §8/§8a, 资料/reverse/mt29-telock,
// 资料/reverse/t41-telock); no closed-source decompiled code is reproduced.
// The decoder below mirrors the x86 instruction semantics at VA 0x436624 in
// the decrypted tool image (telock-layer3.bin), byte-verified by tests.
import { MAX_INPUT, MAX_OUTPUT } from '../bytes.js';
import { requireThat } from '../errors.js';

export const TELOCK_ENGINE = Object.freeze({
  id: 'telock-pe32', family: 'tElock', variants: Object.freeze(['0.9x-wrapper']),
  outputKind: 'none', runtimeVerified: false, stage: 'research',
});

// Honest capability boundary. supportsTelock stays false and unpackTelock
// rejects until a real tElock-packed target sample (not the unpacker tool's
// own image) plus a golden exist; layer transforms and the codec grammar are
// verified independently of that.
export const TELOCK_ENGINE_BOUNDARY = Object.freeze({
  supports: 'always false: the archive holds no tElock-packed target sample; the only tElock-wrapped binary is tElock脱壳机.exe itself (sha256 3c70bf02…), which is the unpacker tool, not a packed target',
  layers: 'L1..L4 wrapper dword transforms replay the tool image byte-for-byte into the MT27/MT29 golden chain (73eb373a…/e3df4acb…/ef1423e0…/ff7e93f1…)',
  codec: 'aPLib-family bitstream grammar recovered by static disassembly of 0x436624 in the decrypted image; no tElock payload stream is statically reachable, so stream decoding is validated on synthetic vectors only',
  loader: 'blocked at runtime values: L1 pushal register image, kernel32 return-address seed at [esp+0x24], runtime-resolved API slots, SEH-driven flow — needs the emulated-pe32 route (P1)',
});

// Wrapper dword layers. Each writes `count` dwords walking firstVa down by 4;
// window[0] is the lowest written VA and equals the next layer's entry
// (lower-window-edge chaining, byte-verified for L1→L2→L3, structural for
// L3→L4). Transform order: preAdd, xors, postSub, postAdd (all mod 2^32).
export const TELOCK_WRAPPER_LAYERS = Object.freeze([
  Object.freeze({
    index: 1, entryVa: 0x436001, firstVa: 0x436975, count: 0x201,
    window: Object.freeze([0x436175, 0x436975]), nextEntryVa: 0x436175,
    preAdd: 0x1c7081e5, xors: Object.freeze([0x7f9944ba, 0x690f1f6b]),
  }),
  Object.freeze({
    index: 2, entryVa: 0x436175, firstVa: 0x436973, count: 459,
    window: Object.freeze([0x43624b, 0x436973]), nextEntryVa: 0x43624b,
    xors: Object.freeze([0x1609a670, 0x7d722de9]), postSub: 0x5ed0ba6e,
  }),
  Object.freeze({
    index: 3, entryVa: 0x43624b, firstVa: 0x436973, count: 392,
    window: Object.freeze([0x436357, 0x436973]), nextEntryVa: 0x436357,
    preAdd: 0xfd03cb06,
  }),
  Object.freeze({
    index: 4, entryVa: 0x436357, firstVa: 0x436973, count: 331,
    window: Object.freeze([0x43644b, 0x436973]), nextEntryVa: 0x436451,
    preAdd: 0x43cbbce4, xors: Object.freeze([0x6da5154d]), postAdd: 0x0255b802,
  }),
]);

// File-offset mapping for the verified tool image only: its last section
// (.data, RVA 0x36000) is file-backed at raw 0x10600 and the wrapper layer
// windows live inside it.
export function telockToolFileOffset(va) {
  const offset = va - 0x436000 + 0x10600;
  return va >= 0x436000 && offset < 0x100000000 ? offset : -1;
}

export function transformTelockDword(layer, word) {
  requireThat(Number.isInteger(word) && word >= 0 && word <= 0xffffffff, 'invalid-input');
  let value = (word + (layer.preAdd || 0)) >>> 0;
  if (layer.xors) for (const mask of layer.xors) value = (value ^ mask) >>> 0;
  if (layer.postSub !== undefined) value = (value - layer.postSub) >>> 0;
  if (layer.postAdd !== undefined) value = (value + layer.postAdd) >>> 0;
  return value >>> 0;
}

function applyLayer(image, layer, offsetOf) {
  requireThat(image instanceof Uint8Array && image.length <= MAX_INPUT, 'input-size-limit');
  requireThat(Number.isInteger(layer.firstVa) && Number.isInteger(layer.count) && layer.count > 0, 'invalid-layer');
  const next = image.slice();
  for (let k = 0; k < layer.count; k++) {
    const at = offsetOf(layer.firstVa - 4 * k);
    requireThat(Number.isInteger(at) && at >= 0 && at + 4 <= next.length, 'telock-window-out-of-range');
    const word = (next[at] | (next[at + 1] << 8) | (next[at + 2] << 16) | (next[at + 3] << 24)) >>> 0;
    const value = transformTelockDword(layer, word);
    next[at] = value & 0xff;
    next[at + 1] = (value >>> 8) & 0xff;
    next[at + 2] = (value >>> 16) & 0xff;
    next[at + 3] = (value >>> 24) & 0xff;
  }
  return next;
}

// Replays wrapper layers 1..`through` over a copy of `bytes`; sha256 values
// are hex strings so callers never depend on node:crypto here.
export function applyTelockWrapperLayers(bytes, { through = 4, offsetOf = telockToolFileOffset, sha256 } = {}) {
  requireThat(bytes instanceof Uint8Array && bytes.length > 0 && bytes.length <= MAX_INPUT, 'input-size-limit');
  requireThat(Number.isInteger(through) && through >= 0 && through <= TELOCK_WRAPPER_LAYERS.length, 'invalid-layer');
  requireThat(typeof offsetOf === 'function', 'invalid-input');
  let image = bytes;
  const layers = [];
  for (const layer of TELOCK_WRAPPER_LAYERS) {
    if (layer.index > through) break;
    image = applyLayer(image, layer, offsetOf);
    layers.push({ index: layer.index, writes: layer.count, window: layer.window.slice(), entryVa: layer.entryVa });
  }
  return { bytes: image, layers, imageSha256: typeof sha256 === 'function' ? sha256(image) : undefined };
}

// aPLib-family payload decoder, grammar of the 0x436624 instance in the
// decrypted tool image. MSB-first bitstream; first byte is an unconditional
// literal; tokens:
//   0            literal
//   10 gamma     gamma==2 → repeat last offset, len gamma2
//                gamma>=3 → offset (gamma-3)*256+byte (becomes last), len gamma3
//                           len += 2 if offset<=0x7f, +=1 if 0x500<=offset<0x7d00,
//                           +=2 if offset>=0x7d00
//   110 byte     offset byte>>1, len 2+(byte&1); offset 0 terminates
//   1110 nibble  nibble==0 → literal 0x00, else offset nibble len 1
export function decompressTelockAplib(input, maxOutput) {
  requireThat(input instanceof Uint8Array, 'invalid-input');
  requireThat(input.length <= MAX_INPUT, 'input-size-limit');
  requireThat(Number.isInteger(maxOutput) && maxOutput >= 0 && maxOutput <= MAX_OUTPUT, 'invalid-output-limit');
  let source = 0, written = 0, previous = 0;
  let output = new Uint8Array(Math.min(maxOutput, 4096));
  const byte = () => {
    requireThat(source < input.length, 'truncated-input');
    return input[source++];
  };
  let tag = 0, bits = 0;
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
      requireThat(value <= MAX_OUTPUT + 2, 'telock-integer-overflow');
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
  const emit = value => { reserve(1); output[written++] = value; };
  const copy = (distance, length) => {
    requireThat(distance > 0 && distance <= written, 'invalid-back-reference');
    reserve(length);
    for (let i = 0; i < length; i++, written++) output[written] = output[written - distance];
  };
  emit(byte());
  for (let tokens = 0; tokens <= maxOutput; tokens++) {
    if (!bit()) { emit(byte()); continue; }
    if (!bit()) {
      const lead = gamma();
      if (lead === 2) copy(previous, gamma());
      else {
        const distance = (lead - 3) * 256 + byte();
        previous = distance;
        let length = gamma();
        if (distance >= 0x7d00 || distance <= 0x7f) length += 2;
        else if (distance >= 0x500) length += 1;
        copy(distance, length);
      }
      continue;
    }
    if (!bit()) {
      const value = byte();
      const distance = value >>> 1;
      if (distance === 0) return { bytes: output.slice(0, written), consumed: source };
      previous = distance;
      copy(distance, 2 + (value & 1));
      continue;
    }
    let nibble = 0;
    for (let i = 0; i < 4; i++) nibble = nibble * 2 + bit();
    if (nibble === 0) emit(0);
    else copy(nibble, 1);
  }
  requireThat(false, 'output-limit');
}

// Engine surface: never claims support until a real packed target sample and
// golden arrive. Registration is the integrator's call (engines-server.js).
export function supportsTelock() {
  return false;
}

export function unpackTelock() {
  requireThat(false, 'telock-no-target-sample');
}
