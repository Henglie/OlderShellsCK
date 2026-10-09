// Original integer/flag semantics. Values are unsigned at the operand width.
export const CF = 0x001, PF = 0x004, AF = 0x010, ZF = 0x040, SF = 0x080, DF = 0x400, OF = 0x800;
const ARITHMETIC = CF | PF | AF | ZF | SF | OF;

export function truncate(value, width) {
  return width === 32 ? value >>> 0 : value & (2 ** width - 1);
}
export function signed(value, width) {
  return width === 32 ? value | 0 : (value << (32 - width)) >> (32 - width);
}
function status(result, width) {
  let low = result & 255;
  low ^= low >>> 4; low ^= low >>> 2; low ^= low >>> 1;
  return (result === 0 ? ZF : 0) | (result & 2 ** (width - 1) ? SF : 0) | (!(low & 1) ? PF : 0);
}

export function arithmetic(cpu, operation, a, b, width) {
  a = truncate(a, width); b = truncate(b, width);
  const carry = (operation === 2 || operation === 3) && (cpu.flags & CF) ? 1 : 0;
  let full, result, bits = 0;
  const sign = 2 ** (width - 1), limit = 2 ** width;
  switch (operation) {
    case 0: case 2: // ADD / ADC
      full = a + b + carry; result = truncate(full, width);
      if (full >= limit) bits |= CF;
      if ((~(a ^ b) & (a ^ result) & sign) !== 0) bits |= OF;
      if ((a ^ b ^ result) & 16) bits |= AF;
      break;
    case 3: case 5: case 7: // SBB / SUB / CMP
      full = a - b - carry; result = truncate(full, width);
      if (full < 0) bits |= CF;
      if (((a ^ b) & (a ^ result) & sign) !== 0) bits |= OF;
      if ((a ^ b ^ result) & 16) bits |= AF;
      break;
    case 1: result = truncate(a | b, width); break;
    case 4: result = truncate(a & b, width); break;
    case 6: result = truncate(a ^ b, width); break;
    default: throw new Error('invalid internal ALU operation');
  }
  cpu.flags = (cpu.flags & ~ARITHMETIC) | bits | status(result, width) | 2;
  return result;
}

export function increment(cpu, value, width, decrement = false) {
  const carry = cpu.flags & CF;
  const result = arithmetic(cpu, decrement ? 5 : 0, value, 1, width);
  cpu.flags = (cpu.flags & ~CF) | carry;
  return result;
}

export function condition(flags, code) {
  const c = Boolean(flags & CF), p = Boolean(flags & PF), z = Boolean(flags & ZF);
  const s = Boolean(flags & SF), o = Boolean(flags & OF);
  switch (code) {
    case 0: return o; case 1: return !o;
    case 2: return c; case 3: return !c;
    case 4: return z; case 5: return !z;
    case 6: return c || z; case 7: return !c && !z;
    case 8: return s; case 9: return !s;
    case 10: return p; case 11: return !p;
    case 12: return s !== o; case 13: return s === o;
    case 14: return z || s !== o; case 15: return !z && s === o;
    default: return false;
  }
}

export function shift(cpu, operation, value, count, width) {
  value = truncate(value, width);
  count &= 31;
  if (!count) return value;
  const sign = 2 ** (width - 1);
  let result = value, carry = Boolean(cpu.flags & CF), overflow;
  if (operation <= 3) {
    const effective = count % (width + (operation >= 2 ? 1 : 0));
    if (!effective) {
      // A nonzero full-width ROL/ROR still defines CF; a full carry ring does not.
      if (operation <= 1) cpu.flags = (cpu.flags & ~CF) |
        ((operation === 0 ? value & 1 : value & sign) ? CF : 0);
      return value;
    }
    for (let i = 0; i < effective; i++) {
      if (operation === 0 || operation === 2) {
        const next = Boolean(result & sign);
        result = truncate(result * 2 + (operation === 0 ? Number(next) : Number(carry)), width);
        carry = next;
      } else {
        const next = Boolean(result & 1);
        result = (result >>> 1) + ((operation === 1 ? next : carry) ? sign : 0);
        carry = next;
      }
    }
    if (count === 1) overflow = operation === 0 || operation === 2
      ? Boolean(result & sign) !== carry : Boolean(result & sign) !== Boolean(result & (sign / 2));
    cpu.flags = (cpu.flags & ~CF) | (carry ? CF : 0);
  } else {
    for (let i = 0; i < count; i++) {
      if (operation === 4 || operation === 6) {
        carry = Boolean(result & sign); result = truncate(result * 2, width);
      } else {
        carry = Boolean(result & 1);
        result = truncate(operation === 7 ? signed(result, width) >> 1 : result >>> 1, width);
      }
    }
    if (count === 1) overflow = operation === 7 ? false : operation === 5
      ? Boolean(value & sign) : Boolean(result & sign) !== carry;
    cpu.flags = (cpu.flags & ~(CF | PF | ZF | SF)) | (carry ? CF : 0) | status(result, width);
  }
  if (overflow !== undefined) cpu.flags = (cpu.flags & ~OF) | (overflow ? OF : 0);
  return result >>> 0;
}
