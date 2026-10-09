import { AnalysisError, requireThat } from '../errors.js';
import { EXECUTE } from './memory.js';
import { arithmetic, increment, shift, condition, truncate, signed, CF, PF, AF, ZF, SF, DF, OF } from './alu.js';

export const EAX = 0, ECX = 1, EDX = 2, EBX = 3, ESP = 4, EBP = 5, ESI = 6, EDI = 7;

/** Original, deliberately partial IA-32 interpreter; unsupported means an error. */
export class CPU {
  constructor(memory, { eip = 0, esp = 0, stack = null, maxSteps = 10000000, win32 = null } = {}) {
    requireThat(Number.isSafeInteger(maxSteps) && maxSteps > 0 && maxSteps <= 100000000,
      'invalid-emulation-budget', { budget: 'maxSteps' });
    this.memory = memory;
    this.regs = new Uint32Array(8);
    this.regs[ESP] = esp;
    this.eip = eip >>> 0;
    this.flags = 2;
    this.stack = stack;
    this.maxSteps = maxSteps;
    this.steps = 0;
    this.callDepth = 0;
    this.win32 = win32;
    this.last = null;
    this.instructionStart = this.eip;
    this.instructionBytes = [];
  }

  charge() {
    requireThat(this.steps < this.maxSteps, 'emulation-step-limit',
      { max: this.maxSteps, steps: this.steps, eip: this.instructionStart });
    this.steps++;
  }
  fetch8() {
    if (this.instructionBytes.length === 15) this.unsupported('instruction-too-long');
    const value = this.memory.read8(this.eip, EXECUTE);
    this.instructionBytes.push(value);
    this.eip = (this.eip + 1) >>> 0;
    return value;
  }
  fetch(width) {
    let value = this.fetch8();
    if (width >= 16) value += this.fetch8() * 256;
    if (width === 32) value += this.fetch8() * 65536 + this.fetch8() * 16777216;
    return value >>> 0;
  }
  opcodeHex() { return this.instructionBytes.map(v => v.toString(16).padStart(2, '0')).join(''); }
  unsupported(reason = 'opcode') {
    throw new AnalysisError('unsupported-opcode', { eip: this.instructionStart, opcode: this.opcodeHex(), reason });
  }

  reg(index, width = 32) {
    return width === 8 ? (this.regs[index & 3] >>> (index >= 4 ? 8 : 0)) & 255
      : truncate(this.regs[index], width);
  }
  setReg(index, value, width = 32) {
    if (width === 32) this.regs[index] = value;
    else if (width === 16) this.regs[index] = (this.regs[index] & 0xffff0000) | (value & 65535);
    else {
      const position = index >= 4 ? 8 : 0, i = index & 3;
      this.regs[i] = (this.regs[i] & ~(255 << position)) | ((value & 255) << position);
    }
  }
  readMemory(address, width) {
    return width === 8 ? this.memory.read8(address) : width === 16
      ? this.memory.read16(address) : this.memory.read32(address);
  }
  writeMemory(address, value, width) {
    if (width === 8) this.memory.write8(address, value);
    else if (width === 16) this.memory.write16(address, value);
    else this.memory.write32(address, value);
  }
  read(operand, width) { return operand.register === undefined ? this.readMemory(operand.address, width) : this.reg(operand.register, width); }
  write(operand, value, width) {
    if (operand.register === undefined) this.writeMemory(operand.address, value, width);
    else this.setReg(operand.register, value, width);
  }

  modrm() {
    const byte = this.fetch8(), mod = byte >>> 6, reg = (byte >>> 3) & 7, rm = byte & 7;
    if (mod === 3) return { reg, operand: { register: rm } };
    let base = 0, index = 0, usesEsp = false;
    if (rm === 4) {
      const sib = this.fetch8(), b = sib & 7, i = (sib >>> 3) & 7;
      if (i !== 4) index = this.regs[i] * 2 ** (sib >>> 6);
      if (mod === 0 && b === 5) base = this.fetch(32);
      else { base = this.regs[b]; usesEsp = b === ESP; }
    } else if (mod === 0 && rm === 5) base = this.fetch(32);
    else base = this.regs[rm];
    const displacement = mod === 1 ? signed(this.fetch8(), 8) : mod === 2 ? signed(this.fetch(32), 32) : 0;
    return { reg, operand: { address: (base + index + displacement) >>> 0, usesEsp } };
  }

  checkStack(pointer = this.regs[ESP], size = 0) {
    if (this.stack) requireThat(pointer >= this.stack.base && pointer + size <= this.stack.end,
      'emulation-stack-limit', { esp: pointer, size, base: this.stack.base, end: this.stack.end });
  }
  push(value, width = 32) {
    const next = (this.regs[ESP] - width / 8) >>> 0;
    this.checkStack(next, width / 8);
    this.writeMemory(next, value, width);
    this.regs[ESP] = next;
  }
  pop(width = 32) {
    this.checkStack(this.regs[ESP], width / 8);
    const value = this.readMemory(this.regs[ESP], width);
    this.regs[ESP] = (this.regs[ESP] + width / 8) >>> 0;
    return value;
  }
  transfer(target, kind) {
    this.eip = target >>> 0;
    this.last.kind = kind;
    this.last.target = this.eip;
  }
  relative(width) { const delta = signed(this.fetch(width), width); return (this.eip + delta) >>> 0; }
  call(target, width) {
    this.push(this.eip, width);
    this.callDepth++;
    this.transfer(width === 16 ? target & 65535 : target, 'call');
  }
  ret(width, cleanup = 0) {
    const target = this.pop(width);
    this.regs[ESP] = (this.regs[ESP] + cleanup) >>> 0;
    this.callDepth = Math.max(0, this.callDepth - 1);
    this.transfer(target, 'return');
  }

  imul(a, b, width) {
    a = signed(a, width); b = signed(b, width);
    const result = width === 32 ? Math.imul(a, b) >>> 0 : truncate(a * b, width);
    const overflow = a * b !== signed(result, width);
    this.flags = (this.flags & ~(CF | OF)) | (overflow ? CF | OF : 0);
    return result;
  }

  string(opcode, width, repeat) {
    const size = width / 8, change = this.flags & DF ? -size : size;
    const count = repeat ? this.regs[ECX] : 1;
    for (let i = 0; i < count; i++) {
      // Each REP element consumes fuel, including overlapping copies and scans.
      if (i) this.charge();
      switch (opcode & 0xfe) {
        case 0xa4:
          this.writeMemory(this.regs[EDI], this.readMemory(this.regs[ESI], width), width);
          this.regs[ESI] += change; this.regs[EDI] += change; break;
        case 0xa6:
          arithmetic(this, 7, this.readMemory(this.regs[ESI], width), this.readMemory(this.regs[EDI], width), width);
          this.regs[ESI] += change; this.regs[EDI] += change; break;
        case 0xaa:
          this.writeMemory(this.regs[EDI], this.reg(EAX, width), width);
          this.regs[EDI] += change; break;
        case 0xac:
          this.setReg(EAX, this.readMemory(this.regs[ESI], width), width);
          this.regs[ESI] += change; break;
        case 0xae:
          arithmetic(this, 7, this.reg(EAX, width), this.readMemory(this.regs[EDI], width), width);
          this.regs[EDI] += change; break;
        default: this.unsupported();
      }
      if (repeat) {
        this.regs[ECX]--;
        if ((opcode & 0xfe) === 0xa6 || (opcode & 0xfe) === 0xae) {
          if (repeat === 0xf3 ? !(this.flags & ZF) : Boolean(this.flags & ZF)) break;
        }
      }
    }
  }

  extended(width) {
    const opcode = this.fetch8();
    if (opcode >= 0x80 && opcode <= 0x8f) {
      const target = this.relative(width);
      if (condition(this.flags, opcode & 15)) this.transfer(width === 16 ? target & 65535 : target, 'conditional-jump');
    } else if (opcode >= 0xc8 && opcode <= 0xcf) {
      if (width !== 32) this.unsupported('16-bit-bswap');
      const value = this.regs[opcode & 7];
      this.regs[opcode & 7] = (value >>> 24) | ((value >>> 8) & 0xff00) | ((value << 8) & 0xff0000) | (value << 24);
    } else {
      if (!(opcode >= 0x90 && opcode <= 0x9f) && !(opcode >= 0x40 && opcode <= 0x4f) &&
        ![0xb6, 0xb7, 0xbe, 0xbf, 0xaf, 0x1f].includes(opcode)) this.unsupported();
      const { reg, operand } = this.modrm();
      if (opcode >= 0x90 && opcode <= 0x9f) this.write(operand, Number(condition(this.flags, opcode & 15)), 8);
      else if (opcode >= 0x40 && opcode <= 0x4f) {
        const value = this.read(operand, width);
        if (condition(this.flags, opcode & 15)) this.setReg(reg, value, width);
      } else if ([0xb6, 0xb7, 0xbe, 0xbf].includes(opcode)) {
        const sourceWidth = opcode & 1 ? 16 : 8, value = this.read(operand, sourceWidth);
        this.setReg(reg, opcode & 8 ? signed(value, sourceWidth) : value, width);
      } else if (opcode === 0xaf) this.setReg(reg, this.imul(this.reg(reg, width), this.read(operand, width), width), width);
      else if (opcode !== 0x1f || reg !== 0) this.unsupported();
    }
  }

  multiplyDivide(operation, operand, width) {
    const value = this.read(operand, width), bits = BigInt(width), mask = (1n << bits) - 1n;
    const low = width === 8 ? this.reg(EAX, 8) : this.reg(EAX, width);
    const high = width === 8 ? this.reg(4, 8) : this.reg(EDX, width);
    let result, remainder;
    if (operation === 4 || operation === 5) {
      result = BigInt(operation === 5 ? signed(low, width) : low) * BigInt(operation === 5 ? signed(value, width) : value);
      const overflow = operation === 4 ? result > mask : result !== BigInt(signed(Number(result & mask), width));
      this.flags = (this.flags & ~(CF | OF)) | (overflow ? CF | OF : 0);
      remainder = (result >> bits) & mask;
      result &= mask;
    } else {
      const divisor = BigInt(operation === 7 ? signed(value, width) : value);
      requireThat(divisor !== 0n, 'emulation-divide-error');
      let dividend = (BigInt(high) << bits) | BigInt(low);
      if (operation === 7 && (high & 2 ** (width - 1))) dividend -= 1n << (bits * 2n);
      result = dividend / divisor; remainder = dividend % divisor;
      const min = operation === 7 ? -(1n << (bits - 1n)) : 0n;
      const max = operation === 7 ? (1n << (bits - 1n)) - 1n : mask;
      requireThat(result >= min && result <= max, 'emulation-divide-error');
    }
    if (width === 8) this.setReg(EAX, Number((result & mask) | ((remainder & mask) << bits)), 16);
    else { this.setReg(EAX, Number(result), width); this.setReg(EDX, Number(remainder), width); }
  }

  execute(opcode, width, repeat) {
    if (repeat && ![0xa4, 0xa5, 0xa6, 0xa7, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf, 0x90].includes(opcode)) {
      this.unsupported('rep-on-non-string');
    }
    if (opcode <= 0x3f && (opcode & 7) <= 5) {
      const operation = opcode >>> 3, form = opcode & 7, bits = opcode & 1 ? width : 8;
      if (form < 4) {
        const { reg, operand } = this.modrm(), register = { register: reg };
        const destination = form & 2 ? register : operand, source = form & 2 ? operand : register;
        const result = arithmetic(this, operation, this.read(destination, bits), this.read(source, bits), bits);
        if (operation !== 7) this.write(destination, result, bits);
      } else {
        const result = arithmetic(this, operation, this.reg(EAX, bits), this.fetch(bits), bits);
        if (operation !== 7) this.setReg(EAX, result, bits);
      }
    } else if (opcode >= 0x40 && opcode <= 0x4f) {
      this.setReg(opcode & 7, increment(this, this.reg(opcode & 7, width), width, Boolean(opcode & 8)), width);
    } else if (opcode >= 0x50 && opcode <= 0x57) this.push(this.reg(opcode & 7, width), width);
    else if (opcode >= 0x58 && opcode <= 0x5f) this.setReg(opcode & 7, this.pop(width), width);
    else if (opcode >= 0x70 && opcode <= 0x7f) {
      const target = this.relative(8);
      if (condition(this.flags, opcode & 15)) this.transfer(target, 'conditional-jump');
    } else if (opcode >= 0x91 && opcode <= 0x97) {
      const a = this.reg(EAX, width), b = this.reg(opcode & 7, width);
      this.setReg(EAX, b, width); this.setReg(opcode & 7, a, width);
    } else if (opcode >= 0xb0 && opcode <= 0xbf) this.setReg(opcode & 7, this.fetch(opcode < 0xb8 ? 8 : width), opcode < 0xb8 ? 8 : width);
    else switch (opcode) {
      case 0x0f: this.extended(width); break;
      case 0x60: {
        const originalEsp = this.reg(ESP, width);
        for (let i = 0; i < 8; i++) this.push(i === ESP ? originalEsp : this.reg(i, width), width);
        break;
      }
      case 0x61:
        for (let i = 7; i >= 0; i--) { const value = this.pop(width); if (i !== ESP) this.setReg(i, value, width); }
        break;
      case 0x68: this.push(this.fetch(width), width); break;
      case 0x6a: this.push(signed(this.fetch8(), 8), width); break;
      case 0x69: case 0x6b: {
        const { reg, operand } = this.modrm(), immediate = opcode === 0x69 ? this.fetch(width) : signed(this.fetch8(), 8);
        this.setReg(reg, this.imul(this.read(operand, width), immediate, width), width); break;
      }
      case 0x80: case 0x81: case 0x83: {
        const { reg, operand } = this.modrm(), bits = opcode === 0x80 ? 8 : width;
        const immediate = opcode === 0x83 ? signed(this.fetch8(), 8) : this.fetch(bits);
        const result = arithmetic(this, reg, this.read(operand, bits), immediate, bits);
        if (reg !== 7) this.write(operand, result, bits); break;
      }
      case 0x84: case 0x85: {
        const { reg, operand } = this.modrm(), bits = opcode & 1 ? width : 8;
        arithmetic(this, 4, this.read(operand, bits), this.reg(reg, bits), bits); break;
      }
      case 0x86: case 0x87: {
        const { reg, operand } = this.modrm(), bits = opcode & 1 ? width : 8;
        const a = this.reg(reg, bits), b = this.read(operand, bits);
        this.write(operand, a, bits); this.setReg(reg, b, bits); break;
      }
      case 0x88: case 0x89: case 0x8a: case 0x8b: {
        const { reg, operand } = this.modrm(), bits = opcode & 1 ? width : 8;
        if (opcode & 2) this.setReg(reg, this.read(operand, bits), bits);
        else this.write(operand, this.reg(reg, bits), bits); break;
      }
      case 0x8d: {
        const { reg, operand } = this.modrm();
        if (operand.register !== undefined) this.unsupported('lea-register');
        this.setReg(reg, operand.address, width); break;
      }
      case 0x8f: {
        const { reg, operand } = this.modrm();
        if (reg !== 0) this.unsupported();
        const value = this.pop(width);
        if (operand.usesEsp) operand.address = (operand.address + width / 8) >>> 0;
        this.write(operand, value, width); break;
      }
      case 0x90: break;
      case 0x98: this.setReg(EAX, signed(this.reg(EAX, width / 2), width / 2), width); break;
      case 0x99: this.setReg(EDX, signed(this.reg(EAX, width), width) < 0 ? -1 : 0, width); break;
      case 0x9c: this.push(this.flags, width); break;
      case 0x9d: this.flags = (this.pop(width) & 0x0cd5) | 2; break;
      case 0x9e: this.flags = (this.flags & ~0xd5) | (this.reg(4, 8) & 0xd5) | 2; break;
      case 0x9f: this.setReg(4, (this.flags & 0xd5) | 2, 8); break;
      case 0xa0: case 0xa1: case 0xa2: case 0xa3: {
        const address = this.fetch(32), bits = opcode & 1 ? width : 8;
        if (opcode & 2) this.writeMemory(address, this.reg(EAX, bits), bits);
        else this.setReg(EAX, this.readMemory(address, bits), bits); break;
      }
      case 0xa8: case 0xa9: {
        const bits = opcode & 1 ? width : 8;
        arithmetic(this, 4, this.reg(EAX, bits), this.fetch(bits), bits); break;
      }
      case 0xa4: case 0xa5: case 0xa6: case 0xa7: case 0xaa: case 0xab: case 0xac: case 0xad: case 0xae: case 0xaf:
        this.string(opcode, opcode & 1 ? width : 8, repeat); break;
      case 0xc0: case 0xc1: case 0xd0: case 0xd1: case 0xd2: case 0xd3: {
        const { reg, operand } = this.modrm(), bits = opcode & 1 ? width : 8;
        const count = opcode < 0xd0 ? this.fetch8() : opcode < 0xd2 ? 1 : this.reg(ECX, 8);
        this.write(operand, shift(this, reg, this.read(operand, bits), count, bits), bits); break;
      }
      case 0xc2: { const cleanup = this.fetch(16); this.ret(width, cleanup); break; }
      case 0xc3: this.ret(width); break;
      case 0xc6: case 0xc7: {
        const { reg, operand } = this.modrm(), bits = opcode & 1 ? width : 8;
        if (reg !== 0) this.unsupported();
        this.write(operand, this.fetch(bits), bits); break;
      }
      case 0xc9:
        this.regs[ESP] = this.regs[EBP]; this.setReg(EBP, this.pop(width), width); break;
      case 0xe0: case 0xe1: case 0xe2: case 0xe3: {
        const target = this.relative(8);
        if (opcode !== 0xe3) this.regs[ECX]--;
        const take = opcode === 0xe3 ? this.regs[ECX] === 0 : this.regs[ECX] !== 0 &&
          (opcode === 0xe2 || (opcode === 0xe1 ? Boolean(this.flags & ZF) : !(this.flags & ZF)));
        if (take) this.transfer(target, 'conditional-jump'); break;
      }
      case 0xe8: { const target = this.relative(width); this.call(target, width); break; }
      case 0xe9: { const target = this.relative(width); this.transfer(width === 16 ? target & 65535 : target, 'jump'); break; }
      case 0xeb: this.transfer(this.relative(8), 'jump'); break;
      case 0xf5: this.flags ^= CF; break;
      case 0xf6: case 0xf7: {
        const { reg, operand } = this.modrm(), bits = opcode & 1 ? width : 8;
        if (reg === 0) arithmetic(this, 4, this.read(operand, bits), this.fetch(bits), bits);
        else if (reg === 2) this.write(operand, ~this.read(operand, bits), bits);
        else if (reg === 3) this.write(operand, arithmetic(this, 5, 0, this.read(operand, bits), bits), bits);
        else if (reg >= 4) this.multiplyDivide(reg, operand, bits);
        else this.unsupported(); break;
      }
      case 0xf8: this.flags &= ~CF; break;
      case 0xf9: this.flags |= CF; break;
      case 0xfc: this.flags &= ~DF; break;
      case 0xfd: this.flags |= DF; break;
      case 0xfe: case 0xff: {
        const { reg, operand } = this.modrm(), bits = opcode === 0xfe ? 8 : width;
        if (reg <= 1) this.write(operand, increment(this, this.read(operand, bits), bits, reg === 1), bits);
        else if (opcode === 0xff && reg === 2) this.call(this.read(operand, width), width);
        else if (opcode === 0xff && reg === 4) this.transfer(this.read(operand, width), 'jump');
        else if (opcode === 0xff && reg === 6) this.push(this.read(operand, width), width);
        else this.unsupported(); break;
      }
      default: this.unsupported();
    }
  }

  step() {
    this.instructionStart = this.eip;
    this.instructionBytes = [];
    this.last = { eip: this.eip, opcode: null, kind: 'linear' };
    try {
      this.charge();
      if (this.win32?.has(this.eip)) {
        this.last.kind = 'shadow-api';
        this.win32.dispatch(this);
      } else {
        let opcode, width = 32, repeat = 0;
        for (;;) {
          opcode = this.fetch8();
          if (opcode === 0x66) width = 16;
          else if (opcode === 0xf2 || opcode === 0xf3) repeat = opcode;
          // PE32 flat CS/DS/ES/SS only; FS/GS, address-size and LOCK are explicit errors.
          else if (![0x26, 0x2e, 0x36, 0x3e].includes(opcode)) break;
        }
        this.last.opcode = opcode;
        this.execute(opcode, width, repeat);
      }
      this.checkStack();
      this.last.size = this.instructionBytes.length;
      return this.last;
    } catch (error) {
      if (error instanceof AnalysisError) error.details = {
        eip: this.instructionStart, opcode: this.opcodeHex(), steps: this.steps, ...error.details,
      };
      throw error;
    }
  }
}
