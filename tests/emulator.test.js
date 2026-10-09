import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { Worker } from 'node:worker_threads';
import { AnalysisError } from '../src/core/errors.js';
import { Bytes } from '../src/core/bytes.js';
import { parsePE } from '../src/core/pe.js';
import { Memory, READ, WRITE, EXECUTE } from '../src/core/emulation/memory.js';
import { CPU, EAX, ECX, EDX, EBX, ESP, EBP, ESI, EDI } from '../src/core/emulation/cpu.js';
import { CF, PF, AF, ZF, SF, OF, DF } from '../src/core/emulation/alu.js';
import { ShadowWin32, SHADOW_APIS } from '../src/core/emulation/win32.js';
import { emulationLimits } from '../src/core/emulation/limits.js';
import { parseEmulatedPE, loadPE, dumpPE, parseFsgEmulatedPE, loadFsgPE } from '../src/core/emulation/pe-loader.js';
import { inspectProfile, TerminalMonitor } from '../src/core/emulation/profiles.js';
import { supportsEmulated, unpackEmulated, EMULATED_ENGINE } from '../src/core/unpackers/emulated.js';

const hash = bytes => createHash('sha256').update(bytes).digest('hex');
const hex = value => Uint8Array.from(value.replace(/\s/g, '').match(/../g) ?? [], pair => Number.parseInt(pair, 16));
const errorCode = code => error => error instanceof AnalysisError && error.code === code;
const arithmeticFlags = CF | PF | AF | ZF | SF | OF;
const fixtureRoot = new URL('../test-results/fixtures/upx/', import.meta.url);
const packed = new Uint8Array(await readFile(new URL('lbop20.upx.bin', fixtureRoot)));
const secondPacked = new Uint8Array(await readFile(new URL('lab18-01.upx.bin', fixtureRoot)));
const golden = new Uint8Array(await readFile(new URL('lbop20.golden.bin', fixtureRoot)));
assert.equal(hash(packed), 'e844ea038a39d448b7a803196f6aa5eaf8697dc48b3305a9b28d544784029158');
assert.equal(hash(secondPacked), '2ac6635a26049d354c0c46243f6451e6594b130745a08c5a99e96a64fbbbec0f');
assert.equal(hash(golden), '5b8cc03b22d3bf8d00e600300ece15359dc10148d474f988b643c5ae863d0163');
const fsgRoot = new URL('../test-results/fixtures/fsg/', import.meta.url);
const fsg131 = new Uint8Array(await readFile(new URL('fsg131.bin', fsgRoot)));
const fsg133 = new Uint8Array(await readFile(new URL('fsg133.bin', fsgRoot)));
const golden131 = new Uint8Array(await readFile(new URL('golden131.bin', fsgRoot)));
const golden133 = new Uint8Array(await readFile(new URL('golden133.bin', fsgRoot)));
assert.equal(hash(fsg131), '28bdbc5f4268464845940e0e7c5c473af9cc1562ce573ce7a8050c3da024611b');
assert.equal(hash(fsg133), '31889f7e66102544c199eb1fe3454641accf7844909b4252e9d9076b4a5803b1');
assert.equal(hash(golden131), '91b9912775aca11b09633fb4913032900ac5fac56571db9021fa8786150f7df0');
assert.equal(hash(golden133), '717b82d5f602b7001720223cfbf2f2366a3680346ea146e06bf7b3be9d9cf6ed');

function machine(program, { maxSteps = 10000, stackSize = 4096, maxWriteBytes, maxMemory } = {}) {
  const memory = new Memory({ maxWriteBytes, maxMemory });
  const code = memory.map(0x1000, 4096, { permissions: READ | EXECUTE, label: 'code' });
  const stack = memory.map(0x8000, stackSize, { label: 'stack' });
  const data = memory.map(0x10000, 4096, { permissions: READ | WRITE, label: 'data', trackWrites: true });
  const bytes = typeof program === 'string' ? hex(program) : Uint8Array.from(program);
  memory.initialize(code.base, bytes);
  const cpu = new CPU(memory, { eip: code.base, esp: stack.end - 16, stack, maxSteps });
  return { memory, cpu, stack, data, end: code.base + bytes.length,
    run() { while (cpu.eip !== this.end) cpu.step(); return cpu; } };
}

function shadowMachine(options) {
  const m = machine('ffd0', options);
  const win32 = new ShadowWin32(m.memory);
  m.cpu.win32 = win32;
  m.kernel = win32.module('KERNEL32.DLL'); m.win32 = win32;
  m.api = (name, args = [], handle = m.kernel) => {
    const initialEsp = m.cpu.regs[ESP];
    m.cpu.eip = 0x1000;
    for (let i = args.length - 1; i >= 0; i--) m.cpu.push(args[i]);
    m.cpu.regs[EAX] = win32.resolve(handle, name);
    m.cpu.step(); // actual FF D0 CALL, followed by a shadow gateway dispatch
    m.cpu.step();
    assert.equal(m.cpu.eip, 0x1002);
    assert.equal(m.cpu.regs[ESP], initialEsp, `${name} stdcall cleanup`);
    assert.equal(m.cpu.callDepth, 0);
    return m.cpu.regs[EAX];
  };
  return m;
}

function compareRvas(output, oracle, start, size) {
  const a = parsePE(output), b = parsePE(oracle);
  let same = 0;
  for (let i = 0; i < size; i++) {
    const rva = start + i, x = a.rvaToOffset(rva), y = b.rvaToOffset(rva);
    assert.notEqual(x, null, `output RVA 0x${rva.toString(16)}`);
    assert.notEqual(y, null, `golden RVA 0x${rva.toString(16)}`);
    same += Number(output[x] === oracle[y]);
  }
  return { same, total: size, percent: 100 * same / size };
}

// golden133 carries e_lfanew 0x0c (an FSG 1.33 quirk kept by the unpacked
// sample), outside the strict parser; map golden RVAs from its section table.
function goldenRvaMap(oracle) {
  const view = new DataView(oracle.buffer, oracle.byteOffset, oracle.byteLength);
  const nt = view.getUint32(0x3c, true), table = nt + 24 + view.getUint16(nt + 20, true);
  const sections = [];
  for (let i = 0; i < view.getUint16(nt + 6, true); i++) {
    const h = table + i * 40;
    sections.push({ rva: view.getUint32(h + 12, true), raw: view.getUint32(h + 16, true), off: view.getUint32(h + 20, true) });
  }
  return rva => {
    for (const s of sections) { const d = rva - s.rva; if (d >= 0 && d < s.raw) return s.off + d; }
    return null;
  };
}

function compareFsgDestination(output, oracle, start, size) {
  const map = goldenRvaMap(oracle);
  let same = 0, total = 0;
  for (let i = 0; i < size; i++) {
    const g = map(start + i);
    assert.notEqual(g, null, `golden RVA 0x${(start + i).toString(16)}`);
    total++;
    same += Number(output[start + i] === oracle[g]); // emulated dump keeps raw offset == RVA
  }
  return { same, total, percent: 100 * same / total };
}

test('MOV ModRM/SIB: scaled index, no base, signed disp8, disp32, absolute memory, LEA', () => {
  const m = machine('bb40000100 b902000000 c7448bf855443322 8b548bf8 8db48520000000 8b04cd40000100 c605010001007f');
  m.cpu.regs[EAX] = 3; m.cpu.regs[EBP] = 0x10000;
  m.memory.write32(0x10050, 0xfedcba98);
  m.run();
  assert.equal(m.memory.read32(0x10040), 0x22334455);
  assert.equal(m.cpu.regs[EDX], 0x22334455);
  assert.equal(m.cpu.regs[ESI], 0x1002c);
  assert.equal(m.cpu.regs[EAX], 0xfedcba98);
  assert.equal(m.memory.read8(0x10001), 0x7f);
});

test('byte high registers and operand-size override preserve untouched register bits', () => {
  const m = machine('b878563412 b4ab b012 66b9aa55 86c4');
  m.cpu.regs[ECX] = 0xaabbccdd; m.run();
  assert.equal(m.cpu.regs[EAX], 0x123412ab);
  assert.equal(m.cpu.regs[ECX], 0xaabb55aa);
  const n = machine('0fbec4 0fb6c8 0fbfd0');
  n.cpu.regs[EAX] = 0x8055; n.run();
  assert.equal(n.cpu.regs[EAX], 0xffffff80);
  assert.equal(n.cpu.regs[ECX], 0x80);
  assert.equal(n.cpu.regs[EDX], 0xffffff80);
});

test('ADC consumes CF preserved by INC/DEC: the NRV refill carry chain', () => {
  const m = machine('f9 41 11db 49');
  m.cpu.regs[ECX] = 0xffffffff; m.cpu.regs[EBX] = 0x80000000;
  m.cpu.step(); m.cpu.step();
  assert.equal(m.cpu.regs[ECX], 0); assert.ok(m.cpu.flags & CF);
  m.cpu.step();
  assert.equal(m.cpu.regs[EBX], 1);
  assert.equal(m.cpu.flags & arithmeticFlags, CF | OF);
  m.cpu.step(); assert.ok(m.cpu.flags & CF);
});

test('independent 8-bit ALU vectors: carry, borrow, signed overflow, parity and auxiliary carry', () => {
  const vectors = [
    ['1400', 0xff, CF, 0, CF | PF | AF | ZF],
    ['1400', 0x7f, CF, 0x80, OF | AF | SF],
    ['1cff', 0, CF, 0, CF | PF | AF | ZF],
    ['2c01', 0x80, 0, 0x7f, OF | AF],
    ['0401', 0xff, 0, 0, CF | PF | AF | ZF],
    ['3403', 0x80, CF | OF, 0x83, SF],
    ['3c01', 0, 0, 0, CF | PF | AF | SF], // CMP sets flags but preserves AL.
  ];
  for (const [program, initial, flags, result, expectedFlags] of vectors) {
    const m = machine(program);
    m.cpu.regs[EAX] = 0x12345600 | initial; m.cpu.flags = flags | 2;
    m.run();
    assert.equal(m.cpu.regs[EAX], (0x12345600 | result) >>> 0, program);
    assert.equal(m.cpu.flags & arithmeticFlags, expectedFlags, program);
  }
});

test('all 16 Jcc predicates in short and near forms use signed/unsigned flags correctly', () => {
  const cases = [
    [0, new Set([1, 3, 5, 7, 9, 11, 13, 15])],
    [CF | ZF | SF | OF | PF, new Set([0, 2, 4, 6, 8, 10, 13, 14])],
    [SF, new Set([1, 3, 5, 7, 8, 11, 12, 14])],
    [OF, new Set([0, 3, 5, 7, 9, 11, 12, 14])],
  ];
  for (const [flags, taken] of cases) for (let cc = 0; cc < 16; cc++) for (const near of [false, true]) {
    const jump = near ? [0x0f, 0x80 + cc, 5, 0, 0, 0] : [0x70 + cc, 5];
    const m = machine([...jump, 0xb8, 1, 0, 0, 0]);
    m.cpu.regs[EAX] = 0x12345678; m.cpu.flags = flags | 2; m.run();
    assert.equal(m.cpu.regs[EAX], taken.has(cc) ? 0x12345678 : 1, `${near ? 'near' : 'short'} Jcc ${cc}`);
  }
});

test('CALL/RET imm16: exact return address, stack cleanup and call depth', () => {
  const m = machine('e8fb0f0000');
  m.memory.map(0x2000, 4096, { permissions: READ | EXECUTE });
  m.memory.initialize(0x2000, hex('b878563412 c20800'));
  const initial = m.cpu.regs[ESP];
  m.cpu.push(0xaa); m.cpu.push(0xbb); m.cpu.step();
  assert.equal(m.cpu.eip, 0x2000); assert.equal(m.cpu.callDepth, 1);
  assert.equal(m.memory.read32(m.cpu.regs[ESP]), 0x1005);
  m.cpu.step(); m.cpu.step();
  assert.equal(m.cpu.eip, 0x1005); assert.equal(m.cpu.regs[ESP], initial);
  assert.equal(m.cpu.regs[EAX], 0x12345678); assert.equal(m.cpu.callDepth, 0);
});

test('PUSHAD/POPAD saves original ESP and ignores its restoration slot', () => {
  const m = machine('60 61'), initial = m.cpu.regs[ESP];
  for (const reg of [EAX, ECX, EDX, EBX, EBP, ESI, EDI]) m.cpu.regs[reg] = 0x10203040 + reg;
  const registers = Uint32Array.from(m.cpu.regs);
  m.cpu.step();
  assert.equal(m.memory.read32(m.cpu.regs[ESP] + 12), initial);
  m.memory.write32(m.cpu.regs[ESP] + 12, 0xdeadbeef);
  for (const reg of [EAX, ECX, EDX, EBX, EBP, ESI, EDI]) m.cpu.regs[reg] = 0;
  m.cpu.step(); assert.deepEqual(m.cpu.regs, registers);
});

test('PUSH ESP and POP [ESP] use the architectural pre-push/post-pop pointer', () => {
  const m = machine('54 8f0424'), initial = m.cpu.regs[ESP]; m.run();
  assert.equal(m.cpu.regs[ESP], initial);
  assert.equal(m.memory.read32(initial), initial);
});

test('shifts and rotates: operand width, CF/OF, arithmetic sign and zero masked count', () => {
  const vectors = [
    ['d0e0', 0x81, 0, 2, CF | OF],
    ['d0e8', 0x81, 0, 0x40, CF | OF],
    ['d0f8', 0x81, OF, 0xc0, CF],
    ['d0d0', 0x80, CF, 1, CF | OF],
    ['c0c008', 1, 0, 1, CF],
    ['c0c808', 0x80, 0, 0x80, CF],
    ['c0e020', 0x81, CF | OF, 0x81, CF | OF],
  ];
  for (const [program, initial, flags, result, carryOverflow] of vectors) {
    const m = machine(program); m.cpu.regs[EAX] = initial; m.cpu.flags = flags | 2; m.run();
    assert.equal(m.cpu.regs[EAX], result, program);
    assert.equal(m.cpu.flags & (CF | OF), carryOverflow, program);
  }
  const m = machine('66c1e808 c1c010 86c4');
  m.cpu.regs[EAX] = 0x12345607; m.run();
  assert.equal(m.cpu.regs[EAX], 0x00563412); // Actual UPX 0x26 byte permutation.
});

test('REP MOVSB observes forward overlap, DF reverse copy and per-element fuel', () => {
  const m = machine('f3a4');
  m.memory.write8(0x10000, 0x5a);
  m.cpu.regs[ESI] = 0x10000; m.cpu.regs[EDI] = 0x10001; m.cpu.regs[ECX] = 7;
  m.run();
  assert.deepEqual(m.data.bytes.subarray(0, 8), new Uint8Array(8).fill(0x5a));
  assert.equal(m.cpu.steps, 7); assert.equal(m.cpu.regs[ECX], 0);
  const n = machine('fdf3a4');
  n.memory.initialize(0x10000, hex('11223344'));
  n.cpu.regs[ESI] = 0x10003; n.cpu.regs[EDI] = 0x10013; n.cpu.regs[ECX] = 4;
  n.run(); assert.deepEqual(n.data.bytes.subarray(16, 20), hex('11223344'));
  assert.equal(n.cpu.regs[ESI], 0xffff); assert.ok(n.cpu.flags & DF);
});

test('REPNE SCASB and REPE CMPSB stop on match/mismatch; ECX=0 accesses no memory', () => {
  const m = machine('f2ae');
  m.memory.initialize(0x10000, hex('61620063')); m.cpu.regs[EDI] = 0x10000; m.cpu.regs[ECX] = 100;
  m.run(); assert.equal(m.cpu.regs[EDI], 0x10003); assert.equal(m.cpu.regs[ECX], 97); assert.ok(m.cpu.flags & ZF);
  const n = machine('f3a6');
  n.memory.initialize(0x10000, hex('112233')); n.memory.initialize(0x10010, hex('11223344'));
  n.cpu.regs[ESI] = 0x10000; n.cpu.regs[EDI] = 0x10010; n.cpu.regs[ECX] = 4;
  n.run(); assert.equal(n.cpu.steps, 4); assert.equal(n.cpu.regs[ECX], 0); assert.ok(!(n.cpu.flags & ZF));
  const zero = machine('f3a5'); zero.cpu.regs[ECX] = 0; zero.cpu.regs[ESI] = 0xffffffff;
  zero.run(); assert.equal(zero.cpu.steps, 1); assert.equal(zero.cpu.regs[ESI], 0xffffffff);
});

test('REP STOSD/LODSD and LOOP preserve flags while updating pointers/count', () => {
  const m = machine('f3ab ad b903000000 e2fe');
  m.cpu.regs[EAX] = 0x10203040; m.cpu.regs[EDI] = 0x10010; m.cpu.regs[ESI] = 0x10010;
  m.cpu.regs[ECX] = 2; m.cpu.flags = CF | ZF | 2; m.run();
  assert.equal(m.memory.read32(0x10010), 0x10203040); assert.equal(m.memory.read32(0x10014), 0x10203040);
  assert.equal(m.cpu.regs[ESI], 0x10014); assert.equal(m.cpu.regs[EDI], 0x10018);
  assert.equal(m.cpu.regs[ECX], 0); assert.equal(m.cpu.flags, CF | ZF | 2);
});

test('MUL/IDIV and divide overflow reject rather than fabricate a result', () => {
  const m = machine('f7e3'); m.cpu.regs[EAX] = 0x10000; m.cpu.regs[EBX] = 0x10000; m.run();
  assert.equal(m.cpu.regs[EAX], 0); assert.equal(m.cpu.regs[EDX], 1); assert.ok(m.cpu.flags & CF);
  const n = machine('f7fb'); n.cpu.regs[EAX] = 0xfffffff9; n.cpu.regs[EDX] = 0xffffffff; n.cpu.regs[EBX] = 3; n.run();
  assert.equal(n.cpu.regs[EAX], 0xfffffffe); assert.equal(n.cpu.regs[EDX], 0xffffffff);
  const bad = machine('f7f3'); bad.cpu.regs[EDX] = 1; bad.cpu.regs[EBX] = 1;
  assert.throws(() => bad.run(), errorCode('emulation-divide-error'));
});

test('unsupported instructions carry exact EIP/opcode; FS/SSE/RDTSC/UD2 are not fake no-ops', () => {
  for (const program of ['0f31', '0f0b', '0f10c0', '64a100000000', '67a4', 'f090', 'cc', 'f4']) {
    const m = machine(program);
    assert.throws(() => m.run(), error => errorCode('unsupported-opcode')(error) && error.details.eip === 0x1000 &&
      typeof error.details.opcode === 'string' && program.startsWith(error.details.opcode));
  }
});

test('memory protects read/write/execute, prevents 32-bit wrap and accounts write tracking', () => {
  const memory = new Memory({ maxMemory: 5000 });
  const region = memory.map(0x1000, 4096, { permissions: READ, trackWrites: true });
  assert.equal(memory.allocated, 4096 + 1 + 512);
  assert.throws(() => memory.write8(0x1000, 1), errorCode('emulation-memory-fault'));
  assert.throws(() => memory.read8(0x1000, EXECUTE), errorCode('emulation-memory-fault'));
  assert.throws(() => memory.read32(0xffffffff), errorCode('emulation-memory-fault'));
  assert.throws(() => memory.map(0x2000, 4096), errorCode('emulation-memory-limit'));
  assert.equal(memory.protect(0x1000, 1, READ | WRITE), READ);
  memory.write16(0x1001, 0xabcd); assert.equal(memory.wasWritten(0x1001, 2), true);
  assert.equal(memory.wasWritten(0x1000, 1), false); assert.equal(region.writtenCount, 2);
});

test('step, REP, stack and cumulative memory-write budgets halt independently', () => {
  const loop = machine('ebfe', { maxSteps: 7 });
  assert.throws(() => loop.run(), error => errorCode('emulation-step-limit')(error) && error.details.steps === 7);
  const rep = machine('f3aa', { maxSteps: 3 }); rep.cpu.regs[ECX] = 100; rep.cpu.regs[EDI] = 0x10000;
  assert.throws(() => rep.run(), errorCode('emulation-step-limit'));
  assert.equal(rep.cpu.regs[ECX], 97); assert.equal(rep.memory.writeBytes, 3);
  const stack = machine('50ebfd', { stackSize: 256, maxSteps: 1000 });
  assert.throws(() => stack.run(), errorCode('emulation-stack-limit'));
  const writes = machine('f3aa', { maxWriteBytes: 2 }); writes.cpu.regs[ECX] = 3; writes.cpu.regs[EDI] = 0x10000;
  assert.throws(() => writes.run(), errorCode('emulation-write-limit')); assert.equal(writes.memory.writeBytes, 2);
});

test('shadow LoadLibrary/GetProcAddress: symbolic resolution and stdcall return/argument cleanup', () => {
  const m = shadowMachine();
  m.memory.initialize(0x10000, hex('7573657233322e646c6c00')); // user32.dll
  const user = m.api('LoadLibraryA', [0x10000]); assert.notEqual(user, 0);
  m.memory.initialize(0x10020, hex('4d657373616765426f784100')); // MessageBoxA
  const address = m.api('GetProcAddress', [user, 0x10020]); assert.ok(m.win32.has(address));
  assert.equal(m.win32.addresses.get(address).implemented, false);
  assert.equal(m.api('GetModuleHandleA', [0x10000]), user);
  assert.equal(m.api('GetModuleHandleA', [0]), 0x400000);
  assert.equal(m.api('GetCurrentProcess'), 0xffffffff);
  assert.equal(m.api('IsDebuggerPresent'), 0);
  assert.equal(SHADOW_APIS.length, 21);
});

test('shadow VirtualProtect returns old PAGE flags to caller scratch; permissions are restored', () => {
  const m = shadowMachine(), initialEsp = m.cpu.regs[ESP]; m.cpu.push(0);
  const oldPointer = m.cpu.regs[ESP];
  assert.equal(m.api('VirtualProtect', [0x10000, 4096, 2, oldPointer]), 1);
  assert.equal(m.memory.read32(oldPointer), 4); assert.equal(m.cpu.regs[ESP], initialEsp - 4);
  assert.throws(() => m.memory.write8(0x10000, 1), errorCode('emulation-memory-fault'));
  assert.equal(m.api('VirtualProtect', [0x10000, 4096, 4, oldPointer]), 1);
  assert.equal(m.memory.read32(oldPointer), 2); m.memory.write8(0x10000, 1);
  assert.equal(m.api('VirtualProtect', [0x20000, 16, 4, oldPointer]), 0);
  assert.equal(m.api('GetLastError'), 487);
});

test('shadow VirtualAlloc commits independent zero memory; release invalidates it', () => {
  const m = shadowMachine();
  const address = m.api('VirtualAlloc', [0, 100, 0x3000, 4]);
  assert.equal(address, 0x50000000); assert.equal(m.memory.read32(address), 0);
  m.memory.write32(address, 0x12345678);
  assert.equal(m.api('VirtualFree', [address, 0, 0x8000]), 1);
  assert.throws(() => m.memory.read32(address), errorCode('emulation-memory-fault'));
  assert.throws(() => m.api('VirtualAlloc', [0, 4096, 0x2000, 4]), errorCode('unsupported-api-operation'));
});

test('unimplemented and unknown DLL APIs/ordinals explicitly refuse execution', () => {
  for (const [dll, api] of [['kernel32.dll', 'CreateThread'], ['user32.dll', 'MessageBoxA'], ['other.dll', 'VirtualProtect'], ['other.dll', 17]]) {
    const m = shadowMachine();
    const handle = m.win32.module(dll);
    assert.throws(() => m.api(api, [], handle), error => errorCode('unsupported-api')(error) &&
      error.details.dll === dll && error.details.api === api && Number.isInteger(error.details.eip));
  }
});

test('shadow last-error/API/allocation state is per-instance, even at identical guest addresses', () => {
  const a = shadowMachine(), b = shadowMachine();
  a.api('SetLastError', [13]); b.api('SetLastError', [47]);
  assert.equal(a.api('GetLastError'), 13); assert.equal(b.api('GetLastError'), 47);
  const x = a.api('VirtualAlloc', [0, 16, 0x3000, 4]), y = b.api('VirtualAlloc', [0, 16, 0x3000, 4]);
  assert.equal(x, y); a.memory.write32(x, 0x11223344); b.memory.write32(y, 0xaabbccdd);
  assert.equal(a.memory.read32(x), 0x11223344); assert.equal(b.memory.read32(y), 0xaabbccdd);
  assert.notEqual(a.win32.entries, b.win32.entries); assert.notEqual(a.cpu.regs.buffer, b.cpu.regs.buffer);
});

test('symbolic FreeLibrary reference counts and allocation page rounding have real state effects', () => {
  const m = shadowMachine();
  m.memory.initialize(0x10000, hex('7573657233322e646c6c00'));
  const user = m.api('LoadLibraryA', [0x10000]);
  assert.equal(m.api('LoadLibraryA', [0x10000]), user);
  assert.equal(m.api('FreeLibrary', [user]), 1);
  assert.equal(m.api('GetModuleHandleA', [0x10000]), user);
  assert.equal(m.api('FreeLibrary', [user]), 1);
  assert.equal(m.api('GetModuleHandleA', [0x10000]), 0);
  assert.equal(m.api('FreeLibrary', [user]), 0);
  const address = m.api('VirtualAlloc', [0, 8192, 0x3000, 4]);
  assert.equal(m.api('VirtualAlloc', [address + 4097, 15, 0x1000, 2]), address + 4096);
  assert.throws(() => m.memory.write8(address + 4097, 1), errorCode('emulation-memory-fault'));
});

test('PE loader maps headers/sections/BSS, an isolated stack and loader-only shadow IAT writes', () => {
  const before = Uint8Array.from(packed), pe = parseEmulatedPE(packed), state = loadPE(packed, pe);
  assert.equal(pe.sizeOfHeaders, 0x400); assert.equal(pe.emulatedHeadersNormalized, true);
  assert.equal(state.memory.read16(state.base), 0x5a4d);
  assert.equal(state.memory.read8(state.base + 0x1000), 0);
  assert.equal(state.memory.read8(state.base + pe.entryPointRva, EXECUTE), 0x60);
  assert.equal(state.memory.read8(state.base + 0x10000), packed[0x400]);
  const thunk = state.memory.read32(state.base + pe.imports[0].firstThunk);
  assert.equal(state.win32.addresses.get(thunk).api, 'LoadLibraryA');
  assert.equal(state.image.writtenCount, 0); assert.deepEqual(packed, before);
  assert.throws(() => state.memory.read8(state.base, EXECUTE), errorCode('emulation-memory-fault'));
});

test('preliminary support refuses wrong architecture/directories/ambiguous layout and bad cached PE', () => {
  assert.equal(supportsEmulated(packed), true); assert.equal(supportsEmulated(secondPacked), true);
  for (const bytes of [null, [], new Uint8Array(), new Uint8Array(512)]) assert.equal(supportsEmulated(bytes), false);
  assert.equal(supportsEmulated(packed, {}), false);
  assert.equal(supportsEmulated(packed, parseEmulatedPE(packed)), true);
  const pe = parseEmulatedPE(packed);
  for (const change of [
    b => new Bytes(b).put16(pe.peOffset + 4, 0x8664),
    b => new Bytes(b).put16(pe.peOffset + 22, 0x2000),
    b => new Bytes(b).put32(pe.directoryOffset + 9 * 8, 0x1000),
    b => new Bytes(b).put32(pe.sections[2].headerOffset + 12, 0x1000),
    b => new Bytes(b).put32(pe.sections[1].headerOffset + 20, 0x200),
  ]) { const bytes = Uint8Array.from(packed); change(bytes); assert.equal(supportsEmulated(bytes), false); }
});

test('terminal monitor ignores destination subcalls and isolated FF 64 24 thunk bytes', () => {
  const pe = parseEmulatedPE(packed), state = loadPE(packed, pe), profile = inspectProfile(packed, pe);
  const monitor = new TerminalMonitor(profile, state);
  assert.equal(monitor.observe({ eip: state.cpu.eip, kind: 'call', opcode: 0xe8, target: state.base + profile.originalEntryPoint }), false);
  state.memory.write32(state.base + profile.originalEntryPoint, 0x002464ff);
  assert.equal(monitor.observe({ eip: state.base + profile.originalEntryPoint, kind: 'jump', opcode: 0xff, target: state.cpu.eip }), false);
  assert.equal(monitor.eof, false); assert.equal(monitor.stopped, false);
  assert.throws(() => monitor.observe({ eip: profile.finalJump, kind: 'jump', opcode: 0xe9,
    target: state.base + profile.originalEntryPoint }), errorCode('emulation-invalid-terminal-state'));
});

test('an actual pre-decoder destination CALL/RET or FF 64 24 JMP executes without an OEP stop', () => {
  const pe = parseEmulatedPE(packed), state = loadPE(packed, pe), profile = inspectProfile(packed, pe);
  const monitor = new TerminalMonitor(profile, state), caller = state.base + pe.sections[1].rva;
  const target = state.base + profile.originalEntryPoint, program = hex('e80000000090');
  new Bytes(program).put32(1, target - caller - 5);
  state.memory.initialize(caller, program); state.memory.initialize(target, hex('c3'));
  state.cpu.eip = caller;
  assert.equal(monitor.observe(state.cpu.step()), false);
  assert.equal(state.cpu.eip, target); assert.equal(state.cpu.callDepth, 1);
  assert.equal(monitor.observe(state.cpu.step()), false);
  assert.equal(state.cpu.eip, caller + 5); assert.equal(state.cpu.callDepth, 0);
  assert.equal(monitor.eof, false); assert.equal(monitor.stopped, false);
  state.memory.initialize(target, hex('ff642400')); state.cpu.eip = caller;
  assert.equal(monitor.observe(state.cpu.step()), false);
  assert.equal(monitor.observe(state.cpu.step()), false);
  assert.equal(state.cpu.eip, caller + 5); assert.equal(state.cpu.callDepth, 1);
  assert.equal(monitor.stopped, false);
});

test('real UPX stub executes decoder, filter, imports, relocation and verified tail to independent golden', t => {
  const before = Uint8Array.from(packed), start = performance.now();
  const result = unpackEmulated(packed, 'lbop20.exe'), elapsed = performance.now() - start;
  const pe = parsePE(result.bytes), m = result.metadata;
  const text = compareRvas(result.bytes, golden, 0x1000, 0xb200);
  let same = 0, total = 0;
  for (const section of pe.sections) {
    const matched = compareRvas(result.bytes, golden, section.rva, section.rawSize);
    same += matched.same; total += matched.total;
  }
  assert.equal(text.same, 45568); assert.equal(text.percent, 100);
  assert.equal(total, 102400); assert.equal(same, 102124); assert.ok(same / total > 0.85);
  assert.equal(m.engine, 'emulated-pe32'); assert.equal(m.mode, 'emulated'); assert.equal(m.outputKind, 'dump-pe');
  assert.equal(m.runtimeVerified, false); assert.equal(m.stopReason, 'verified-upx-tail-transfer');
  assert.equal(m.originalEntryPoint, 0x1252); assert.equal(pe.entryPointRva, 0x1252);
  assert.equal(m.steps, 955810); assert.equal(m.decompressedSize, 93445);
  assert.equal(m.shadowApiCalls, 68);
  assert.deepEqual(m.shadowApis, [
    { api: 'kernel32.dll!LoadLibraryA', calls: 2 }, { api: 'kernel32.dll!GetProcAddress', calls: 64 },
    { api: 'kernel32.dll!VirtualProtect', calls: 2 },
  ]);
  assert.equal(m.importsRebuilt, false); assert.ok(m.warnings.includes('imports-not-rebuilt'));
  assert.ok(m.warnings.includes('resources-not-rebuilt')); assert.deepEqual(pe.warnings, []);
  assert.ok(pe.sections.every(s => s.rawOffset === s.rva)); assert.equal(result.bytes.length, 106496);
  assert.deepEqual(packed, before);
  t.diagnostic(`UPX: steps=${m.steps}, elapsedMs=${elapsed.toFixed(2)}, mappedSections=${same}/${total} (${(100 * same / total).toFixed(6)}%), text=45568/45568`);
});

test('golden comparator follows raw/RVA mapping even when independent disk raw offsets move', () => {
  const p = parsePE(golden), moved = new Uint8Array(golden.length + 0x200), out = new Bytes(moved);
  moved.set(golden.subarray(0, p.sizeOfHeaders));
  for (const s of p.sections) {
    moved.set(golden.subarray(s.rawOffset, s.rawOffset + s.rawSize), s.rawOffset + 0x200);
    out.put32(s.headerOffset + 20, s.rawOffset + 0x200);
  }
  const result = unpackEmulated(packed);
  assert.equal(compareRvas(result.bytes, moved, 0x1000, 0xb200).same, 45568);
});

test('second real UPX variant without relocations/packheader has an independently identified terminal jump', () => {
  const result = unpackEmulated(secondPacked, 'lab18-01.exe'), pe = parsePE(result.bytes);
  assert.equal(result.metadata.steps, 306319); assert.equal(result.metadata.originalEntryPoint, 0x154f);
  assert.equal(result.metadata.decompressedSize, 29793); assert.equal(pe.entryPointRva, 0x154f);
  assert.equal(result.metadata.stopReason, 'verified-upx-tail-transfer'); assert.deepEqual(pe.warnings, []);
});

test('two live executions interleaved in one realm keep CPU/memory/stack/API state independent', () => {
  const inputs = [packed, secondPacked], states = inputs.map(bytes => loadPE(bytes, parseEmulatedPE(bytes)));
  const monitors = states.map((state, i) => new TerminalMonitor(inspectProfile(inputs[i], state.pe), state));
  const done = [false, false];
  assert.notEqual(states[0].memory.regions, states[1].memory.regions);
  assert.notEqual(states[0].stack.bytes.buffer, states[1].stack.bytes.buffer);
  while (!done.every(Boolean)) for (let i = 0; i < 2; i++) if (!done[i]) {
    for (let tick = 0; tick < 997 && !done[i]; tick++) done[i] = monitors[i].observe(states[i].cpu.step());
  }
  assert.equal(states[0].cpu.steps, 955810); assert.equal(states[1].cpu.steps, 306319);
  assert.equal(states[0].cpu.eip, 0x401252); assert.equal(states[1].cpu.eip, 0x40154f);
  const first = dumpPE(states[0], monitors[0].profile.originalEntryPoint), second = dumpPE(states[1], monitors[1].profile.originalEntryPoint);
  assert.equal(compareRvas(first, golden, 0x1000, 0xb200).same, 45568);
  const untouched = Uint8Array.from(second); first.fill(0); assert.deepEqual(second, untouched);
});

function workerUnpack(bytes, name) {
  return new Promise((resolve, reject) => {
    const worker = new Worker(new URL('./fixtures/emulator-worker.js', import.meta.url), { workerData: { bytes, name } });
    worker.once('message', message => message.error ? reject(Object.assign(new Error(message.error.code), message.error)) : resolve(message.result));
    worker.once('error', reject);
    worker.once('exit', code => { if (code) reject(new Error(`emulator worker exit ${code}`)); });
  });
}

test('two actual worker threads unpack different input buffers in parallel with deterministic independent output', async () => {
  const [first, second] = await Promise.all([workerUnpack(packed, 'first.exe'), workerUnpack(secondPacked, 'second.exe')]);
  assert.equal(first.metadata.steps, 955810); assert.equal(second.metadata.steps, 306319);
  assert.deepEqual(first, unpackEmulated(packed, 'first.exe'));
  assert.deepEqual(second, unpackEmulated(secondPacked, 'second.exe'));
  assert.notEqual(first.bytes.buffer, second.bytes.buffer);
  first.bytes[0] = 0; assert.equal(second.bytes[0], 0x4d); assert.equal(packed[0], 0x4d);
});

test('exact input subview and independent output ownership are deterministic', () => {
  const padded = new Uint8Array(packed.length + 19); padded.set(packed, 7);
  const first = unpackEmulated(padded.subarray(7, 7 + packed.length)), second = unpackEmulated(packed);
  assert.deepEqual(first, second); first.bytes.fill(0);
  assert.equal(second.bytes[0], 0x4d); assert.equal(packed[0], 0x4d); assert.equal(EMULATED_ENGINE.id, 'emulated-pe32');
});

test('public input/output/memory/steps/writes/API budgets reject before returning an artifact', () => {
  const cases = [
    [{ maxInput: packed.length - 1 }, 'input-size-limit'],
    [{ maxOutput: 4096 }, 'emulation-output-limit'],
    [{ maxMemory: 4096 }, 'emulation-memory-limit'],
    [{ maxSteps: 999 }, 'emulation-step-limit'],
    [{ maxWriteBytes: 32 }, 'emulation-write-limit'],
    [{ maxApiEntries: 4 }, 'emulation-api-limit'],
    [{ maxApiCalls: 2 }, 'emulation-api-call-limit'],
  ];
  for (const [options, code] of cases) assert.throws(() => unpackEmulated(packed, 'budget.exe', options), errorCode(code));
  for (const options of [{ maxSteps: 0 }, { maxSteps: 100000001 }, { maxMemory: Infinity }, { stackSize: 255 }, { maxOutput: NaN }, { maxSteps: null }]) {
    assert.throws(() => emulationLimits(options), errorCode('invalid-emulation-budget'));
  }
});

test('real accepted profile with an unsupported decoder opcode fails with its actual instruction EIP', () => {
  const bytes = Uint8Array.from(packed), pe = parseEmulatedPE(bytes);
  // First bit-refill MOV, reached from the intact initial JMP: replace with RDTSC.
  bytes[pe.entryPointOffset + 26] = 0x0f; bytes[pe.entryPointOffset + 27] = 0x31;
  assert.equal(supportsEmulated(bytes), true);
  assert.throws(() => unpackEmulated(bytes), error => errorCode('unsupported-opcode')(error) &&
    error.details.eip === Number(pe.imageBase) + pe.entryPointRva + 26 && error.details.opcode === '0f31');
});

test('FSG loader binds packed LoadLibraryA/GetProcAddress IAT slots and injects entry execute', () => {
  for (const [bytes, iatRva, stubByte] of [[fsg131, 0x780c7, 0xbb], [fsg133, 0x780a1, 0xbe]]) {
    const before = Uint8Array.from(bytes), pe = parseFsgEmulatedPE(bytes), state = loadFsgPE(bytes, pe);
    const slot0 = state.memory.read32(state.base + iatRva), slot1 = state.memory.read32(state.base + iatRva + 4);
    assert.ok(state.win32.has(slot0));
    assert.equal(state.win32.addresses.get(slot0).api, 'LoadLibraryA');
    assert.equal(state.win32.addresses.get(slot0).implemented, true);
    assert.ok(state.win32.has(slot1));
    assert.equal(state.win32.addresses.get(slot1).api, 'GetProcAddress');
    assert.equal(state.win32.addresses.get(slot1).implemented, true);
    // Loader IAT binding is not a decoder write; the dump tracks guest writes only.
    assert.equal(state.image.writtenCount, 0);
    assert.equal(state.memory.read8(state.base + pe.entryPointRva, EXECUTE), stubByte);
    // Sections carry no EXECUTE flag (0xC0000020); only the entry section gets it injected.
    assert.throws(() => state.memory.read8(state.base + 0x1000, EXECUTE), errorCode('emulation-memory-fault'));
    assert.deepEqual(bytes, before);
    assert.equal(supportsEmulated(bytes, parseFsgEmulatedPE(bytes)), true);
    assert.equal(supportsEmulated(bytes, {}), false);
  }
});

test('real FSG 1.31 stub emulates aPLib decode, shadow import repair and verified OEP transfer', t => {
  const before = Uint8Array.from(fsg131), start = performance.now();
  const result = unpackEmulated(fsg131, 'fsg131.exe'), elapsed = performance.now() - start;
  const m = result.metadata, pe = parsePE(result.bytes);
  const matched = compareFsgDestination(result.bytes, golden131, 0x1000, 0x50000);
  assert.equal(matched.same, 326308); assert.equal(matched.total, 327680);
  assert.ok(matched.percent > 85); // acceptance threshold; measured 99.5813%
  assert.equal(m.variant, 'FSG 1.31 aPLib stub');
  assert.equal(m.steps, 4497972); assert.equal(m.stopReason, 'verified-fsg-tail-transfer');
  assert.equal(m.originalEntryPoint, 0x40300); assert.equal(m.decompressedSize, 301847);
  assert.equal(m.outputKind, 'dump-pe'); assert.equal(m.runtimeVerified, false);
  assert.equal(m.importsRebuilt, false); assert.equal(m.resourcesRebuilt, false);
  assert.equal(m.shadowApiCalls, 354);
  assert.deepEqual(m.shadowApis, [
    { api: 'kernel32.dll!LoadLibraryA', calls: 11 }, { api: 'kernel32.dll!GetProcAddress', calls: 343 },
  ]);
  assert.ok(m.warnings.includes('fsg-entry-section-execute-injected'));
  assert.ok(m.warnings.includes('fsg-dump-headers-relocated'));
  assert.ok(m.warnings.includes('fsg-overstated-header-size'));
  assert.ok(m.warnings.includes('symbolic-iat-addresses'));
  assert.equal(pe.peOffset, 0x100); assert.equal(pe.entryPointRva, 0x40300);
  assert.deepEqual(pe.warnings, []);
  assert.ok(pe.sections.every(s => s.rawOffset === s.rva));
  assert.equal(result.bytes.length, 495616);
  assert.deepEqual(fsg131, before);
  t.diagnostic(`FSG 1.31: steps=${m.steps}, elapsedMs=${elapsed.toFixed(2)}, destination=${matched.same}/${matched.total} (${matched.percent.toFixed(6)}%)`);
});

test('real FSG 1.33 stub (e_lfanew 0x0c, TLS directory) reaches the same verified terminal state', t => {
  const start = performance.now();
  const result = unpackEmulated(fsg133, 'fsg133.exe'), elapsed = performance.now() - start;
  const m = result.metadata, pe = parsePE(result.bytes);
  const matched = compareFsgDestination(result.bytes, golden133, 0x1000, 0x50000);
  assert.equal(matched.same, 326308); assert.equal(matched.total, 327680);
  assert.ok(matched.percent > 85);
  assert.equal(m.variant, 'FSG 1.33 aPLib stub');
  assert.equal(m.steps, 4501503); assert.equal(m.stopReason, 'verified-fsg-tail-transfer');
  assert.equal(m.originalEntryPoint, 0x40300); assert.equal(m.decompressedSize, 301847);
  assert.deepEqual(m.shadowApis, [
    { api: 'kernel32.dll!LoadLibraryA', calls: 11 }, { api: 'kernel32.dll!GetProcAddress', calls: 343 },
  ]);
  assert.ok(m.warnings.includes('fsg-overlapping-dos-header'));
  assert.equal(pe.peOffset, 0x100); assert.deepEqual(pe.warnings, []);
  assert.equal(result.bytes.length, 495616);
  t.diagnostic(`FSG 1.33: steps=${m.steps}, elapsedMs=${elapsed.toFixed(2)}, destination=${matched.same}/${matched.total} (${matched.percent.toFixed(6)}%)`);
});

test('FSG emulation respects the public step budget before returning an artifact', () => {
  assert.throws(() => unpackEmulated(fsg131, 'budget.exe', { maxSteps: 100 }), errorCode('emulation-step-limit'));
});

test('a corrupted FSG terminal JE refuses profiling rather than fabricating a transfer', () => {
  const pe = parseFsgEmulatedPE(fsg131), bytes = Uint8Array.from(fsg131);
  bytes[pe.entryPointOffset + 218] = 0x85; // 0f 84 -> 0f 85 breaks the vetted plaintext stub
  assert.equal(supportsEmulated(bytes), false);
  assert.throws(() => unpackEmulated(bytes), AnalysisError);
});

test('FSG Lab18-02 early loader variant remains outside the emulated profile', async () => {
  const bytes = new Uint8Array(await readFile(new URL('../test-results/fixtures/fsg/lab18-02.bin', import.meta.url)));
  assert.equal(supportsEmulated(bytes), false);
  assert.throws(() => unpackEmulated(bytes), AnalysisError);
});
