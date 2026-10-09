import { Bytes, matchHex } from '../bytes.js';
import { requireThat } from '../errors.js';

function findUnique(bytes, start, end, pattern) {
  let found = null;
  for (let i = start; i + pattern.length / 2 <= end; i++) if (matchHex(bytes, i, pattern)) {
    requireThat(found === null, 'ambiguous-emulated-stub');
    found = i;
  }
  requireThat(found !== null, 'unsupported-emulated-stub');
  return found;
}

/** Packer-specific terminal-state evidence, not a generic section-exit heuristic. */
export function inspectProfile(bytes, pe) {
  const b = new Bytes(bytes), ep = pe.entryPointOffset, base = Number(pe.imageBase);
  requireThat(ep !== null && pe.rvaToOffset(pe.entryPointRva, 16) === ep &&
    matchHex(bytes, ep, '60be........8dbe........57eb0b90'), 'unsupported-emulated-stub');
  const source = b.u32(ep + 2), destination = source + b.i32(ep + 8);
  const packedSection = pe.sections.find(s => pe.entryPointRva >= s.rva && pe.entryPointRva < s.rva + s.rawSize);
  const targetSection = pe.sections.find(s => base + s.rva === destination && s.rawSize === 0);
  requireThat(packedSection && targetSection && source === base + packedSection.rva &&
    destination + targetSection.virtualSize === source && source < base + pe.entryPointRva,
  'unsupported-emulated-layout');
  const end = Math.min(ep + 2048, packedSection.rawOffset + packedSection.rawSize);
  const eof = findUnique(bytes, ep + 16, end, '83f0ff74..89c5');
  const decoderExit = eof + 5 + (b.u8(eof + 4) << 24 >> 24);
  requireThat(decoderExit >= ep && decoderExit + 8 <= end && matchHex(bytes, decoderExit, '5e89f7b9........'),
    'unsupported-emulated-stub');
  const filterExit = findUnique(bytes, decoderExit, end, '88d8e2..8dbe........8b0709c0') + 4;
  const tail = findUnique(bytes, filterExit, end, '618d4424806a0039c475fa83ec80e9........');
  const finalJump = tail + 14;
  const originalEntryPoint = pe.entryPointRva + finalJump - ep + 5 + b.i32(finalJump + 1);
  requireThat(originalEntryPoint >= targetSection.rva && originalEntryPoint + 16 <= targetSection.rva + targetSection.virtualSize &&
    (targetSection.characteristics & 0x20000000), 'invalid-emulated-oep');
  const va = raw => base + pe.entryPointRva + raw - ep;
  return Object.freeze({ variant: 'UPX PE32 NRV short stub', destination, source,
    eofBranch: va(eof + 3), decoderExit: va(decoderExit), filterExit: va(filterExit),
    popad: va(tail), finalJump: va(finalJump), originalEntryPoint });
}

export class TerminalMonitor {
  constructor(profile, state) {
    this.profile = profile;
    this.state = state;
    this.eof = false;
    this.decodedSize = 0;
    this.filtered = false;
    this.restoredStack = false;
    this.stopped = false;
  }

  observe(last) {
    const { cpu, memory, base, initialEsp } = this.state, p = this.profile;
    if (last.eip === p.eofBranch && last.kind === 'conditional-jump' && last.target === p.decoderExit) {
      requireThat(cpu.regs[0] === 0, 'emulation-invalid-terminal-state');
      this.decodedSize = cpu.regs[7] - p.destination;
      requireThat(this.decodedSize >= 16 && p.destination + this.decodedSize <= p.popad &&
        memory.wasWritten(p.destination, this.decodedSize), 'emulation-incomplete-decoder');
      this.eof = true;
    }
    if (last.eip === p.filterExit) {
      requireThat(this.eof && cpu.regs[1] === 0, 'emulation-incomplete-filter');
      this.filtered = true;
    }
    if (last.eip === p.popad && last.opcode === 0x61) {
      this.restoredStack = cpu.regs[4] === initialEsp;
    }
    if (last.eip !== p.finalJump) return false;
    requireThat(last.kind === 'jump' && last.opcode === 0xe9 && last.target === base + p.originalEntryPoint &&
      this.eof && this.filtered && this.restoredStack && cpu.regs[4] === initialEsp && cpu.callDepth === 0 &&
      memory.wasWritten(base + p.originalEntryPoint, 16), 'emulation-invalid-terminal-state');
    this.stopped = true;
    return true;
  }
}

/** FSG 1.31/1.33 terminal evidence: the statically located `0f 84` JE at the
 *  fixed stub offset (218/161) whose rel32 lands on the golden-verified OEP.
 *  The stub variant is identified by the first stub opcode (bb/be), already
 *  fully matched by the vetted plaintext pattern in unpackers/fsg.js. */
export function inspectFsgProfile(bytes, pe) {
  const ep = pe.entryPointOffset, base = Number(pe.imageBase);
  requireThat(ep !== null && (bytes[ep] === 0xbb || bytes[ep] === 0xbe), 'unsupported-emulated-stub');
  const version = bytes[ep] === 0xbb ? '1.31' : '1.33';
  const je = version === '1.31' ? 218 : 161;
  requireThat(ep + je + 6 <= bytes.length && matchHex(bytes, ep + je, '0f84'), 'unsupported-emulated-stub');
  const originalEntryPoint = pe.entryPointRva + je + 6 + new Bytes(bytes).i32(ep + je + 2);
  const [destination, source] = pe.sections;
  requireThat(originalEntryPoint >= destination.rva &&
    originalEntryPoint + 16 <= destination.rva + destination.virtualSize, 'invalid-emulated-oep');
  return Object.freeze({ variant: `FSG ${version} aPLib stub`,
    originalEntryPoint, oepJump: base + pe.entryPointRva + je,
    destinationStart: base + destination.rva,
    destinationEnd: base + destination.rva + destination.virtualSize,
    sourceStart: base + source.rva, minimumDecodedBytes: destination.virtualSize >> 1 });
}

function countWritten(memory, start, end) {
  const region = memory.locate(start, 1);
  if (!region.written) return 0;
  let count = 0;
  for (let i = start - region.base; i < end - region.base; i++) {
    if (region.written[i >>> 3] & (1 << (i & 7))) count++;
  }
  return count;
}

export class FsgTerminalMonitor {
  constructor(profile, state) {
    this.profile = profile;
    this.state = state;
    this.decodedBytes = 0;
    this.stopped = false;
  }

  observe(last) {
    const { cpu, memory, base, win32 } = this.state, p = this.profile;
    if (last.eip !== p.oepJump || last.kind !== 'conditional-jump' || last.opcode !== 0x0f) return false;
    requireThat(last.target === base + p.originalEntryPoint, 'emulation-invalid-terminal-state');
    // Three independent facts must hold: the decoder actually wrote the
    // destination image at scale, the OEP bytes exist, and the stub really
    // ran its LoadLibraryA/GetProcAddress import repair through shadow gates.
    this.decodedBytes = countWritten(memory, p.destinationStart, p.destinationEnd);
    requireThat(this.decodedBytes >= p.minimumDecodedBytes, 'emulation-incomplete-decoder');
    requireThat(memory.wasWritten(base + p.originalEntryPoint, 16), 'emulation-incomplete-decoder');
    requireThat((win32.used.get('kernel32.dll!LoadLibraryA') ?? 0) >= 1 &&
      (win32.used.get('kernel32.dll!GetProcAddress') ?? 0) >= 1, 'emulation-incomplete-imports');
    requireThat(cpu.callDepth === 0, 'emulation-invalid-terminal-state');
    this.stopped = true;
    return true;
  }
}
