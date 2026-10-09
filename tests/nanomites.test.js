import test from 'node:test';
import assert from 'node:assert/strict';
import { parseArmInlineNan, parseDilloDieRecords, repairNanomites, createFlagProbes,
  createNanomiteProbes, classifyNanomite, applyNanomiteSidecar, parseNanomiteSidecar,
  NANOMITE_LIMITS } from '../src/core/unpackers/nanomites.js';

const BASE = 0x400000, ADDRESS = BASE + 0x40, TARGET = BASE + 0x60;
const hex = text => Uint8Array.from(text.replaceAll(' ', '').match(/../g) ?? [], b => parseInt(b, 16));
const options = { layout: 'raw-rva', imageBase: BASE };
const image = (length = 0x200) => { const b = new Uint8Array(length).fill(0x90); b[0x40] = 0xcc; return b; };
const record = (extra = {}) => ({ address: ADDRESS, destination: TARGET, size: 2, condition: 'jne', ...extra });

// Independent, handwritten x86 truth predicates; never call the implementation's evaluator.
const CONDITIONS = [
  ['jo', 0x70, 23, f => !!(f & 0x800)], ['jno', 0x71, 24, f => !(f & 0x800)],
  ['jb', 0x72, 5, f => !!(f & 1)], ['jae', 0x73, 8, f => !(f & 1)],
  ['je', 0x74, 4, f => !!(f & 0x40)], ['jne', 0x75, 3, f => !(f & 0x40)],
  ['jbe', 0x76, 6, f => !!(f & 0x41)], ['ja', 0x77, 7, f => !(f & 0x41)],
  ['js', 0x78, 17, f => !!(f & 0x80)], ['jns', 0x79, 18, f => !(f & 0x80)],
  ['jp', 0x7a, 13, f => !!(f & 4)], ['jnp', 0x7b, 15, f => !(f & 4)],
  ['jl', 0x7c, 11, f => ((f >>> 7) & 1) !== ((f >>> 11) & 1)],
  ['jge', 0x7d, 10, f => ((f >>> 7) & 1) === ((f >>> 11) & 1)],
  ['jle', 0x7e, 12, f => !!(f & 0x40) || ((f >>> 7) & 1) !== ((f >>> 11) & 1)],
  ['jg', 0x7f, 9, f => !(f & 0x40) && ((f >>> 7) & 1) === ((f >>> 11) & 1)],
];
function independentProbes(predicate, size = 2, target = TARGET) {
  const samples = [];
  for (const ecx of [0, 1, 2, 0x10000]) {
    for (const cf of [0, 1]) for (const pf of [0, 4]) for (const zf of [0, 0x40])
      for (const sf of [0, 0x80]) for (const of of [0, 0x800]) {
        const eflags = 0x202 + cf + pf + zf + sf + of;
        samples.push({ eflags, ecx, eip: predicate(eflags, ecx) ? target : ADDRESS + size });
      }
  }
  return samples;
}

test('ArmInline disk golden is Count + little-endian Address/Destination/Size/JumpType', () => {
  const bytes = hex('02000000 40004000 60004000 02000000 03000000 80004000 40004000 06000000 04000000');
  const records = parseArmInlineNan(bytes);
  assert.deepEqual(records.map(({ source, offset, ...r }) => r), [
    { address: ADDRESS, destination: TARGET, size: 2, jumpType: 3 },
    { address: BASE + 0x80, destination: ADDRESS, size: 6, jumpType: 4 },
  ]);
  const memory = image(); memory[0x80] = 0xcc;
  const output = repairNanomites(memory, records, options);
  assert.deepEqual(output.bytes.slice(0x40, 0x42), hex('75 1e'));
  assert.deepEqual(output.bytes.slice(0x80, 0x86), hex('0f 84 ba ff ff ff'));
  assert.equal(output.repaired.length, 2);
  assert.deepEqual(output.unresolved, []);
});

test('dilloDIE mixed-stride golden uses signed disp8/disp32 and owns its bytes', () => {
  const bytes = hex('40004000 02 75 1e 80004000 05 e9 bbffffff 90004000 06 0f8e aaffffff');
  const records = parseDilloDieRecords(bytes);
  assert.deepEqual(records.map(r => [r.address, r.destination, r.size, r.condition, r.offset]), [
    [ADDRESS, TARGET, 2, 'jne', 0], [BASE + 0x80, ADDRESS, 5, 'jmp', 7], [BASE + 0x90, ADDRESS, 6, 'jle', 17],
  ]);
  bytes.fill(0);
  const memory = image(); memory[0x80] = 0xcc; memory[0x90] = 0xcc;
  const result = repairNanomites(memory, records, options);
  assert.equal(result.repaired.length, 3);
  assert.deepEqual(result.bytes.slice(0x90, 0x96), hex('0f8e aaffffff'));
});

test('record parsers bound counts, exact lengths, views, and allocation budgets', () => {
  assert.throws(() => parseArmInlineNan(hex('ffffffff')), e => e.code === 'nanomite-record-limit');
  assert.throws(() => parseArmInlineNan(hex('01000000')), e => e.code === 'truncated-nan-table');
  assert.throws(() => parseArmInlineNan(hex('00000000 00')), e => e.code === 'trailing-nan-data');
  assert.throws(() => parseArmInlineNan(hex('0000')), e => e.code === 'truncated-nan-table');
  assert.throws(() => parseDilloDieRecords(hex('40004000 06 0f84 0000')), e => e.code === 'truncated-dillo-record');
  assert.throws(() => parseDilloDieRecords(hex('40004000 00')), e => e.code === 'invalid-dillo-size');
  assert.throws(() => parseDilloDieRecords(hex('40004000 02 7501 00')), e => e.code === 'truncated-dillo-record');
  assert.throws(() => parseDilloDieRecords(hex('40004000 02 7501 80004000 02 eb00'), { maxRecords: 1 }), e => e.code === 'nanomite-record-limit');
  assert.throws(() => parseArmInlineNan(hex('00000000'), { maxRecords: NANOMITE_LIMITS.records + 1 }), e => e.code === 'nanomite-record-limit');
  const sliced = hex('aa 00000000 bb').subarray(1, 5);
  assert.deepEqual(parseArmInlineNan(sliced), []);
});

for (const [condition, opcode, jumpType, predicate] of CONDITIONS) {
  test(`${condition}: independent short and near byte goldens; all flags and both EIP outcomes`, () => {
    for (const size of [2, 6]) {
      const samples = independentProbes(predicate, size);
      const classified = classifyNanomite(samples, { address: ADDRESS, size });
      assert.equal(classified.status, 'resolved');
      assert.equal(classified.record.condition, condition);
      assert.equal(classified.record.destination, TARGET);
      const patched = repairNanomites(image(), [{ address: ADDRESS, destination: TARGET, size, jumpType }], options);
      const expected = size === 2 ? [opcode, 0x1e] : [0x0f, opcode + 0x10, 0x1a, 0, 0, 0];
      assert.deepEqual([...patched.bytes.slice(0x40, 0x40 + size)], expected);
      assert.equal(patched.unresolved.length, 0);
      assert.deepEqual(new Set(samples.map(p => p.eip)), new Set([TARGET, ADDRESS + size]));
    }
  });
}

const COUNTER_CONDITIONS = [
  ['loopne', 0xe0, (f, c) => c !== 1 && !(f & 0x40)],
  ['loope', 0xe1, (f, c) => c !== 1 && !!(f & 0x40)],
  ['loop', 0xe2, (_f, c) => c !== 1], ['jecxz', 0xe3, (_f, c) => c === 0],
];
for (const [condition, opcode, predicate] of COUNTER_CONDITIONS) {
  test(`${condition}: dilloDIE opcode golden and full ECX/flags differential`, () => {
    const stream = Uint8Array.from([0x40, 0, 0x40, 0, 2, opcode, 0x1e]);
    const records = parseDilloDieRecords(stream);
    const patched = repairNanomites(image(), records, options);
    assert.deepEqual([...patched.bytes.slice(0x40, 0x42)], [opcode, 0x1e]);
    assert.equal(patched.repaired.length, 1);
    const result = classifyNanomite(independentProbes(predicate), { address: ADDRESS, size: 2 });
    assert.equal(result.status, 'resolved');
    assert.equal(result.record.condition, condition);
  });
}

test('JMP short/near goldens and complete counter probes distinguish unconditional branches', () => {
  for (const size of [2, 5]) {
    const resolved = classifyNanomite(independentProbes(() => true, size), { address: ADDRESS, size });
    assert.equal(resolved.record.condition, 'jmp');
    const result = repairNanomites(image(), [resolved.record], options);
    assert.deepEqual([...result.bytes.slice(0x40, 0x40 + size)], size === 2 ? [0xeb, 0x1e] : [0xe9, 0x1b, 0, 0, 0]);
  }
});

test('probe plans cover exactly 32 flag combinations and 128 independent counter/flag combinations', () => {
  assert.equal(new Set(createFlagProbes().map(f => f & 0x8c5)).size, 32);
  assert.equal(createFlagProbes()[0], 0x202);
  assert.equal(createFlagProbes()[31], 0xac7);
  assert.equal(createNanomiteProbes().length, 128);
  assert.deepEqual(new Set(createNanomiteProbes().map(p => p.ecx)), new Set([0, 1, 2, 0x10000]));
});

test('legacy six-value shortcuts, missing ECX classes, inconsistent and ambiguous EIPs are refused', () => {
  const full = independentProbes(f => !!(f & 0x40));
  const classify = samples => classifyNanomite(samples, { address: ADDRESS, size: 2 });
  assert.equal(classify(full.filter(s => [0x202, 0xac7, 0x282, 0xa02, 0xa82, 0xac2].includes(s.eflags))).reason, 'incomplete-probes');
  assert.equal(classify(full.filter(s => s.ecx === 2)).reason, 'incomplete-probes');
  assert.equal(classify([...full, { ...full[0], eip: ADDRESS + 7 }]).reason, 'inconsistent-observations');
  assert.equal(classify(full.map(s => ({ ...s, eip: ADDRESS + 2 }))).reason, 'ambiguous-target');
  const third = full.map((s, i) => i === 0 ? { ...s, eip: ADDRESS + 7 } : s);
  assert.equal(classify(third).reason, 'inconsistent-observations');
  assert.equal(classify(independentProbes(f => !!(f & 4) && !!(f & 1))).reason, 'unknown-condition');
  assert.equal(classifyNanomite(full, { address: ADDRESS, size: 2, destination: BASE }).reason, 'destination-mismatch');
});

test('backward Jcc does not become JMP; negative rel8 and rel32 have independent byte goldens', () => {
  const target = ADDRESS - 0x20;
  const result = classifyNanomite(independentProbes(f => !(f & 0x40), 2, target), { address: ADDRESS, size: 2 });
  assert.equal(result.record.condition, 'jne');
  assert.deepEqual([...repairNanomites(image(), [result.record], options).bytes.slice(0x40, 0x42)], [0x75, 0xde]);
  assert.deepEqual([...repairNanomites(image(), [record({ size: 6, destination: target })], options).bytes.slice(0x40, 0x46)], [0x0f, 0x85, 0xda, 0xff, 0xff, 0xff]);
});

test('pseudo CC and already-patched sites are rejected without mutating the source', () => {
  const memory = image(); memory[0x40] = 0x75;
  const result = repairNanomites(memory, [record()], options);
  assert.equal(result.unresolved[0].reason, 'site-not-int3');
  assert.deepEqual(result.bytes, memory);
  const operand = image(); operand.set([0xff, 0x15, 0xcc, 0, 0x40, 0], 0x3e);
  assert.equal(repairNanomites(operand, [record()], options).unresolved[0].reason, 'int3-in-indirect-operand');
  const immediate = image(); immediate.set([0xb8, 0xcc, 0, 0, 0], 0x3f);
  assert.equal(repairNanomites(immediate, [record()], { ...options,
    instructionSpans: [{ address: BASE + 0x3f, size: 5 }] }).unresolved[0].reason, 'not-instruction-boundary');
});

test('length, target/site range and rel8 limits are checked before any writes', () => {
  const invalid = [
    [record({ size: 5 }), 'invalid-instruction-length'], [record({ size: 1 }), 'invalid-instruction-length'],
    [record({ destination: BASE + 0x200 }), 'destination-outside-image'],
    [record({ destination: BASE - 1 }), 'destination-outside-image'],
    [record({ address: BASE + 0x1ff }), 'site-outside-image'],
    [record({ destination: ADDRESS + 2 + 128 }), 'rel8-out-of-range'],
  ];
  for (const [r, reason] of invalid) {
    const memory = image(); const output = repairNanomites(memory, [r], options);
    assert.equal(output.unresolved[0].reason, reason);
    assert.deepEqual(output.bytes, memory);
  }
  assert.deepEqual([...repairNanomites(image(), [record({ destination: ADDRESS + 2 + 127 })], options).bytes.slice(0x40, 0x42)], [0x75, 0x7f]);
  const large = image(0x400); large[0x180] = 0xcc;
  assert.deepEqual([...repairNanomites(large, [record({ address: BASE + 0x180, destination: BASE + 0x102 })], options).bytes.slice(0x180, 0x182)], [0x75, 0x80]);
});

test('unknown opcodes, legacy markers, conflicting aliases and unsupported counter widths never guess', () => {
  const records = parseDilloDieRecords(hex('40004000 05 ffffffff00 00000000 05 e900000000'));
  const result = repairNanomites(image(), records, options);
  assert.deepEqual(result.unresolved.map(r => r.reason), ['unknown-opcode', 'marker-record']);
  for (const [jumpType, reason] of [[0, 'unknown-jump-type'], [1, 'not-nanomite'], [19, 'ambiguous-counter-width'],
    [20, 'unsupported-jncxz'], [25, 'unknown-jump-type']]) {
    assert.equal(repairNanomites(image(), [record({ condition: undefined, jumpType })], options).unresolved[0].reason, reason);
  }
  assert.equal(repairNanomites(image(), [record({ jumpType: 4 })], options).unresolved[0].reason, 'ambiguous-record');
  const explicit = repairNanomites(image(), [record({ condition: undefined, jumpType: 19 })], { ...options, counterBits: 32 });
  assert.deepEqual([...explicit.bytes.slice(0x40, 0x42)], [0xe3, 0x1e]);
  for (const jumpType of [14, 16, 21, 22]) assert.equal(repairNanomites(image(), [record({ condition: undefined, jumpType })], options).repaired.length, 1);
});

test('all overlapping records are refused, including duplicate, nested and invalid claims', () => {
  const memory = image(); memory[0x41] = 0xcc; memory[0x45] = 0xcc;
  const records = [record({ size: 6 }), record({ address: ADDRESS + 1, size: 2 }),
    record({ address: ADDRESS + 5, size: 1 }), record(), record({ address: ADDRESS - 1, size: 20 })];
  const result = repairNanomites(memory, records, options);
  assert.equal(result.repaired.length, 0);
  assert.ok(result.unresolved.every(r => r.reason === 'overlapping-records'));
  assert.deepEqual(result.bytes, memory);
});

test('disjoint valid records survive unresolved neighbors and the input/output views are isolated', () => {
  const memory = image(); memory[0x80] = 0xcc;
  const before = Uint8Array.from(memory);
  const result = repairNanomites(memory, [record(), record({ address: BASE + 0x80, condition: 'unknown' })], options);
  assert.equal(result.repaired.length, 1);
  assert.equal(result.unresolved[0].reason, 'unknown-condition');
  assert.equal(result.complete, false);
  assert.deepEqual(memory, before);
  result.bytes.fill(0); result.repaired[0].bytes.fill(0);
  assert.deepEqual(memory, before);
});

test('layout, optional independently decoded boundaries, executable ranges and hard limits are explicit', () => {
  assert.throws(() => repairNanomites(image(), [], { imageBase: BASE }), e => e.code === 'unsupported-image-layout');
  assert.throws(() => repairNanomites(image(), [], { ...options, imageBase: 0xfffffff0 }), e => e.code === 'invalid-image-range');
  assert.equal(repairNanomites(image(), [record()], { ...options, instructionSpans: [] }).unresolved[0].reason, 'unverified-instruction-boundary');
  assert.equal(repairNanomites(image(), [record()], { ...options, executableRanges: [] }).unresolved[0].reason, 'site-not-executable');
  assert.throws(() => repairNanomites(image(), [record(), record()], { ...options, maxRecords: 1 }), e => e.code === 'nanomite-record-limit');
  assert.throws(() => repairNanomites(new Uint8Array(new SharedArrayBuffer(0x200)), [], options), e => e.code === 'shared-input');
});

test('JSON sidecar modes separate supplied records, classified probes and unavailable results', () => {
  const sidecar = { schema: 'armadillo-oracle/v1', layout: 'raw-rva', imageBase: BASE,
    nanRecords: [record()], probes: [], processes: [], status: 'records-ready' };
  const records = applyNanomiteSidecar(image(), JSON.stringify(sidecar), { mode: 'records' });
  assert.equal(records.repaired.length, 1);
  const missing = applyNanomiteSidecar(image(), sidecar, { mode: 'probe' });
  assert.equal(missing.repaired.length, 0);
  assert.equal(missing.unresolved[0].reason, 'probe-unavailable');
  sidecar.status = 'observations-ready';
  sidecar.probes.push({ address: ADDRESS, size: 2, observations: independentProbes(f => !(f & 0x40)) });
  const probes = applyNanomiteSidecar(image(), sidecar, { mode: 'probe' });
  assert.equal(probes.repaired[0].condition, 'jne');
  assert.throws(() => applyNanomiteSidecar(image(), sidecar), e => e.code === 'missing-nanomite-mode');
  assert.throws(() => applyNanomiteSidecar(image(), sidecar, { mode: 'probe', imageBase: BASE + 1 }), e => e.code === 'image-base-mismatch');
  assert.throws(() => parseNanomiteSidecar('{x'), e => e.code === 'invalid-nanomite-sidecar');
  const detached = parseNanomiteSidecar(sidecar); detached.probes[0].observations[0].eip = 1;
  assert.notEqual(sidecar.probes[0].observations[0].eip, 1);
  sidecar.status = 'probe-unavailable';
  assert.equal(applyNanomiteSidecar(image(), sidecar, { mode: 'probe' }).repaired.length, 0);
  assert.throws(() => parseNanomiteSidecar({ ...sidecar, nanRecords: [{ ...record(), encoding: [0x175, 0x1e] }] }), e => e.code === 'invalid-nanomite-encoding');
});

test('rel32 overflow and 32-bit address wrapping are refused by probe classification and dillo parsing', () => {
  const wrapped = parseDilloDieRecords(hex('feffffff 02 eb00'));
  assert.equal(wrapped[0].reason, 'address-overflow');
  const samples = independentProbes(() => true, 5, 0xf0000000);
  assert.equal(classifyNanomite(samples, { address: ADDRESS, size: 5 }).reason, 'unknown-condition');
  assert.equal(classifyNanomite(samples, { address: 0xfffffffe, size: 5 }).reason, 'invalid-probe-site');
});

test('parallel invocations share neither record mutations, flag probes nor image bytes', async () => {
  const shared = image(), original = Uint8Array.from(shared);
  const outputs = await Promise.all(Array.from({ length: 32 }, (_, i) => Promise.resolve().then(() =>
    repairNanomites(shared, [record({ condition: i % 2 ? 'je' : 'jne' })], options))));
  outputs[0].bytes.fill(0);
  for (let i = 1; i < outputs.length; i++) assert.equal(outputs[i].bytes[0x40], i % 2 ? 0x74 : 0x75);
  assert.deepEqual(shared, original);
  const first = createNanomiteProbes(); first[0].eflags = 0;
  assert.equal(createNanomiteProbes()[0].eflags, 0x202);
});
