import { AnalysisError, requireThat } from '../errors.js';

export const READ = 1, WRITE = 2, EXECUTE = 4;
const PAGE = 4096;

/** A per-instance, bounded 32-bit address space. No host addresses are exposed. */
export class Memory {
  constructor({ maxMemory = 128 * 1024 * 1024, maxWriteBytes = 256 * 1024 * 1024 } = {}) {
    requireThat(Number.isSafeInteger(maxMemory) && maxMemory > 0 && maxMemory <= 256 * 1024 * 1024 &&
      Number.isSafeInteger(maxWriteBytes) && maxWriteBytes > 0 && maxWriteBytes <= 1024 * 1024 * 1024,
    'invalid-emulation-budget');
    this.maxMemory = maxMemory;
    this.maxWriteBytes = maxWriteBytes;
    this.allocated = 0;
    this.writeBytes = 0;
    this.regions = [];
    this.cached = null;
  }

  validRange(address, size) {
    return Number.isSafeInteger(address) && Number.isSafeInteger(size) && address >= 0 && size >= 0 &&
      address < 0x100000000 && address + size <= 0x100000000;
  }

  map(base, size, { permissions = READ | WRITE, label = 'memory', trackWrites = false } = {}) {
    requireThat(this.validRange(base, size) && size > 0 && base % PAGE === 0,
      'emulation-invalid-mapping', { base, size });
    requireThat(Number.isInteger(permissions) && permissions >= 0 && permissions <= 7, 'emulation-invalid-protection');
    requireThat(this.regions.length < 1024 && !this.regions.some(r => base < r.end && r.base < base + size),
      'emulation-mapping-overlap', { base, size });
    const pages = Math.ceil(size / PAGE), trackingSize = trackWrites ? Math.ceil(size / 8) : 0;
    const cost = size + pages + trackingSize;
    requireThat(cost <= this.maxMemory - this.allocated, 'emulation-memory-limit',
      { requested: cost, allocated: this.allocated, max: this.maxMemory });
    const region = { base, end: base + size, size, label, cost, bytes: new Uint8Array(size),
      permissions: new Uint8Array(pages).fill(permissions),
      written: trackWrites ? new Uint8Array(trackingSize) : null, writtenCount: 0 };
    region.view = new DataView(region.bytes.buffer);
    this.regions.push(region);
    this.allocated += cost;
    return region;
  }

  locate(address, size = 1, access = 0) {
    if (!this.validRange(address, size)) this.fault(address, size, access);
    let region = this.cached;
    if (!region || address < region.base || address + Math.max(size, 1) > region.end) {
      region = this.regions.find(r => address >= r.base && address + Math.max(size, 1) <= r.end);
      this.cached = region;
    }
    if (!region) this.fault(address, size, access);
    if (access) {
      const first = Math.floor((address - region.base) / PAGE);
      const last = Math.floor((address - region.base + Math.max(size, 1) - 1) / PAGE);
      for (let page = first; page <= last; page++) {
        if ((region.permissions[page] & access) !== access) this.fault(address, size, access);
      }
    }
    return region;
  }

  fault(address, size, access) {
    throw new AnalysisError('emulation-memory-fault', { address, size,
      access: access === EXECUTE ? 'execute' : access === WRITE ? 'write' : 'read' });
  }

  protect(address, size, permissions) {
    requireThat(Number.isInteger(permissions) && permissions >= 0 && permissions <= 7 && size > 0,
      'emulation-invalid-protection');
    const region = this.locate(address, size), offset = address - region.base;
    const first = Math.floor(offset / PAGE), last = Math.floor((offset + size - 1) / PAGE);
    const previous = region.permissions[first];
    region.permissions.fill(permissions, first, last + 1);
    return previous;
  }

  unmap(region) {
    const index = this.regions.indexOf(region);
    requireThat(index !== -1, 'emulation-invalid-mapping');
    this.regions.splice(index, 1);
    this.allocated -= region.cost;
    this.cached = null;
  }

  read8(address, access = READ) {
    const r = this.locate(address, 1, access);
    return r.bytes[address - r.base];
  }
  read16(address, access = READ) {
    const r = this.locate(address, 2, access);
    return r.view.getUint16(address - r.base, true);
  }
  read32(address, access = READ) {
    const r = this.locate(address, 4, access);
    return r.view.getUint32(address - r.base, true);
  }

  recordWrite(region, offset, size) {
    requireThat(size <= this.maxWriteBytes - this.writeBytes, 'emulation-write-limit',
      { max: this.maxWriteBytes, written: this.writeBytes, requested: size });
    this.writeBytes += size;
    if (!region.written) return;
    for (let i = offset; i < offset + size; i++) {
      const byte = i >>> 3, bit = 1 << (i & 7);
      if (!(region.written[byte] & bit)) { region.written[byte] |= bit; region.writtenCount++; }
    }
  }

  write8(address, value) {
    const r = this.locate(address, 1, WRITE), offset = address - r.base;
    this.recordWrite(r, offset, 1);
    r.bytes[offset] = value;
  }
  write16(address, value) {
    const r = this.locate(address, 2, WRITE), offset = address - r.base;
    this.recordWrite(r, offset, 2);
    r.view.setUint16(offset, value, true);
  }
  write32(address, value) {
    const r = this.locate(address, 4, WRITE), offset = address - r.base;
    this.recordWrite(r, offset, 4);
    r.view.setUint32(offset, value, true);
  }

  // Used only by the loader before guest execution; does not mark decoded bytes.
  initialize(address, bytes) {
    requireThat(bytes instanceof Uint8Array, 'invalid-input');
    const r = this.locate(address, bytes.length);
    r.bytes.set(bytes, address - r.base);
  }

  wasWritten(address, size = 1) {
    const r = this.locate(address, size);
    if (!r.written) return false;
    const offset = address - r.base;
    for (let i = offset; i < offset + size; i++) if (!(r.written[i >>> 3] & (1 << (i & 7)))) return false;
    return true;
  }

  string(address, { wide = false, max = 512 } = {}) {
    requireThat(Number.isInteger(max) && max > 0 && max <= 4096, 'emulation-string-limit');
    let result = '';
    for (let i = 0; i < max; i++) {
      const value = wide ? this.read16(address + i * 2) : this.read8(address + i);
      if (!value) return result;
      result += String.fromCharCode(value);
    }
    throw new AnalysisError('emulation-unterminated-string', { address, max });
  }
}
