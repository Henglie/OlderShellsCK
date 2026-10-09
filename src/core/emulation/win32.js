import { AnalysisError, requireThat } from '../errors.js';
import { READ, WRITE, EXECUTE } from './memory.js';

export const SHADOW_APIS = Object.freeze([
  'LoadLibraryA', 'LoadLibraryW', 'LoadLibraryExA', 'LoadLibraryExW',
  'GetModuleHandleA', 'GetModuleHandleW', 'GetProcAddress', 'FreeLibrary',
  'VirtualProtect', 'VirtualAlloc', 'VirtualFree', 'FlushInstructionCache',
  'GetCurrentProcess', 'GetCurrentProcessId', 'GetCurrentThreadId', 'IsDebuggerPresent',
  'GetLastError', 'SetLastError', 'SetErrorMode', 'GetModuleFileNameA', 'GetModuleFileNameW',
]);
const ARGUMENTS = Object.freeze({
  LoadLibraryA: 1, LoadLibraryW: 1, LoadLibraryExA: 3, LoadLibraryExW: 3,
  GetModuleHandleA: 1, GetModuleHandleW: 1, GetProcAddress: 2, FreeLibrary: 1,
  VirtualProtect: 4, VirtualAlloc: 4, VirtualFree: 3, FlushInstructionCache: 3,
  GetCurrentProcess: 0, GetCurrentProcessId: 0, GetCurrentThreadId: 0, IsDebuggerPresent: 0,
  GetLastError: 0, SetLastError: 1, SetErrorMode: 1, GetModuleFileNameA: 3, GetModuleFileNameW: 3,
});
const protectionBits = protection => ({
  1: 0, 2: READ, 4: READ | WRITE, 8: READ | WRITE,
  16: EXECUTE, 32: READ | EXECUTE, 64: READ | WRITE | EXECUTE, 128: READ | WRITE | EXECUTE,
})[protection];
const winProtection = bits => ({ 0: 1, 1: 2, 3: 4, 4: 16, 5: 32, 7: 64 })[bits];

/** Symbolic DLLs and stdcall gateways, never host OS imports or native code. */
export class ShadowWin32 {
  constructor(memory, { imageBase = 0x400000, name = 'input.exe', maxApiEntries = 4096, maxApiCalls = 16384 } = {}) {
    requireThat(Number.isInteger(maxApiEntries) && maxApiEntries > 0 && maxApiEntries <= 16384 &&
      Number.isInteger(maxApiCalls) && maxApiCalls > 0 && maxApiCalls <= 65536, 'invalid-emulation-budget');
    this.memory = memory;
    this.imageBase = imageBase;
    this.name = typeof name === 'string' ? name.slice(0, 4095) : 'input.exe';
    this.maxApiEntries = maxApiEntries;
    this.maxApiCalls = maxApiCalls;
    this.modules = new Map();
    this.handles = new Map();
    this.entries = new Map();
    this.addresses = new Map();
    this.used = new Map();
    this.allocations = new Map();
    this.nextModule = 0;
    this.nextAllocation = 0x50000000;
    this.calls = 0;
    this.nameBytes = 0;
    this.lastError = 0;
    this.errorMode = 0;
  }

  module(name) {
    requireThat(typeof name === 'string' && name.length > 0 && name.length <= 512 && !/[\x00-\x1f]/.test(name),
      'emulation-invalid-module');
    const dll = name.replace(/^.*[\\/]/, '').toLowerCase();
    if (this.modules.has(dll)) {
      const record = this.modules.get(dll); record.references++;
      return record.handle;
    }
    requireThat(this.nextModule < 256, 'emulation-api-limit');
    const handle = 0xe0000000 + this.nextModule++ * 65536;
    const record = { dll, handle, references: 1 };
    this.modules.set(dll, record); this.handles.set(handle, record);
    return handle;
  }

  resolve(handle, api) {
    const module = this.handles.get(handle);
    requireThat(module, 'emulation-invalid-module-handle', { handle });
    requireThat((typeof api === 'string' && api.length > 0 && api.length <= 512 && /^[\x21-\x7e]+$/.test(api)) ||
      (Number.isInteger(api) && api > 0 && api <= 65535), 'emulation-invalid-api-name');
    const key = `${module.dll}!${typeof api === 'number' ? '#' : ''}${api}`;
    if (this.entries.has(key)) return this.entries.get(key).address;
    this.nameBytes += key.length;
    requireThat(this.entries.size < this.maxApiEntries && this.nameBytes <= 1024 * 1024, 'emulation-api-limit');
    const address = 0xf0000000 + this.entries.size * 16;
    const implemented = ['kernel32.dll', 'kernelbase.dll'].includes(module.dll) && typeof api === 'string' &&
      Object.hasOwn(ARGUMENTS, api);
    const entry = { address, dll: module.dll, api, implemented };
    this.entries.set(key, entry); this.addresses.set(address, entry);
    return address;
  }
  has(address) { return this.addresses.has(address); }

  fail(code = 87) { this.lastError = code; return 0; }
  protect(address, size, protection, oldPointer) {
    const bits = protectionBits(protection);
    if (bits === undefined || !size) return this.fail();
    try {
      this.memory.locate(oldPointer, 4, WRITE);
      const previous = this.memory.protect(address, size, bits);
      this.memory.write32(oldPointer, winProtection(previous));
      return 1;
    } catch (error) {
      if (error.code !== 'emulation-memory-fault') throw error;
      return this.fail(487);
    }
  }

  allocate(address, size, type, protection) {
    const bits = protectionBits(protection);
    if (!size || bits === undefined || !type || (type & ~0x3000)) return this.fail();
    if (!(type & 0x1000)) throw new AnalysisError('unsupported-api-operation',
      { api: 'VirtualAlloc', type, reason: 'reserve-only' });
    if (address) {
      try {
        const start = Math.floor(address / 4096) * 4096, extent = address + size - start;
        const region = this.memory.locate(start, extent);
        if (!this.allocations.has(region.base) || type !== 0x1000) return this.fail(487);
        this.memory.protect(start, extent, bits);
        return start;
      } catch (error) {
        if (error.code !== 'emulation-memory-fault') throw error;
      }
    }
    const base = address ? Math.floor(address / 65536) * 65536 : Math.ceil(this.nextAllocation / 65536) * 65536;
    const extent = Math.ceil((size + (address ? address - base : 0)) / 4096) * 4096;
    if (base < 0x50000000 || base + extent > 0x60000000) return this.fail(487);
    if (this.memory.regions.some(r => base < r.end && r.base < base + extent)) return this.fail(487);
    const region = this.memory.map(base, extent, { permissions: bits, label: 'VirtualAlloc' });
    this.allocations.set(base, region); this.nextAllocation = Math.max(this.nextAllocation, base + extent);
    return base;
  }

  free(address, size, type) {
    const region = this.allocations.get(address);
    if (!region) return this.fail(487);
    if (type === 0x8000 && size === 0) {
      this.memory.unmap(region); this.allocations.delete(address); return 1;
    }
    // Decommit is intentionally unsupported: silently preserving committed data is incorrect.
    throw new AnalysisError('unsupported-api-operation', { api: 'VirtualFree', type, size });
  }

  invoke(entry, args) {
    const wide = entry.api.endsWith('W');
    switch (entry.api) {
      case 'LoadLibraryA': case 'LoadLibraryW': case 'LoadLibraryExA': case 'LoadLibraryExW':
        if (args.length === 3 && (args[1] !== 0 || args[2] !== 0)) {
          throw new AnalysisError('unsupported-api-operation', { api: entry.api, flags: args[2] });
        }
        return this.module(this.memory.string(args[0], { wide }));
      case 'GetModuleHandleA': case 'GetModuleHandleW': {
        if (!args[0]) return this.imageBase;
        const dll = this.memory.string(args[0], { wide }).replace(/^.*[\\/]/, '').toLowerCase();
        return this.modules.get(dll)?.handle ?? this.fail(126);
      }
      case 'GetProcAddress':
        if (!this.handles.has(args[0])) return this.fail(126);
        return this.resolve(args[0], args[1] <= 65535 ? args[1] : this.memory.string(args[1]));
      case 'FreeLibrary': {
        const module = this.handles.get(args[0]);
        if (!module) return this.fail(6);
        if (--module.references === 0) {
          this.modules.delete(module.dll); this.handles.delete(module.handle);
        }
        return 1;
      }
      case 'VirtualProtect': return this.protect(...args);
      case 'VirtualAlloc': return this.allocate(...args);
      case 'VirtualFree': return this.free(...args);
      case 'GetCurrentProcess': return 0xffffffff;
      case 'GetCurrentProcessId': case 'GetCurrentThreadId': return 1;
      case 'IsDebuggerPresent': return 0;
      case 'GetLastError': return this.lastError;
      case 'SetLastError': this.lastError = args[0]; return 0;
      case 'SetErrorMode': { const old = this.errorMode; this.errorMode = args[0]; return old; }
      case 'FlushInstructionCache':
        if (args[0] !== 0xffffffff) return this.fail(6);
        if (args[1] && args[2]) this.memory.locate(args[1], args[2]);
        return 1;
      case 'GetModuleFileNameA': case 'GetModuleFileNameW': {
        const module = this.handles.get(args[0]);
        if (args[0] !== 0 && args[0] !== this.imageBase && !module) return this.fail(126);
        const text = module ? module.dll : this.name, capacity = args[2];
        requireThat(capacity <= 4096, 'emulation-string-limit');
        if (!capacity) return this.fail(122);
        const count = Math.min(text.length, capacity - 1);
        for (let i = 0; i <= count; i++) {
          const value = i === count ? 0 : text.charCodeAt(i);
          if (!wide && value > 255) throw new AnalysisError('unsupported-api-operation', { api: entry.api, reason: 'ansi-name' });
          if (wide) this.memory.write16(args[1] + i * 2, value);
          else this.memory.write8(args[1] + i, value);
        }
        if (text.length >= capacity) { this.lastError = 122; return capacity; }
        return count;
      }
      default: throw new AnalysisError('unsupported-api', { dll: entry.dll, api: entry.api });
    }
  }

  dispatch(cpu) {
    const entry = this.addresses.get(cpu.eip);
    requireThat(entry, 'unsupported-api', { address: cpu.eip });
    if (!entry.implemented) throw new AnalysisError('unsupported-api', { dll: entry.dll, api: entry.api, eip: cpu.eip });
    requireThat(this.modules.has(entry.dll), 'unsupported-api-operation', { api: entry.api, reason: 'unloaded-module' });
    requireThat(this.calls < this.maxApiCalls, 'emulation-api-call-limit', { max: this.maxApiCalls });
    this.calls++;
    const argc = ARGUMENTS[entry.api], esp = cpu.regs[4];
    cpu.checkStack(esp, (argc + 1) * 4);
    const args = Array.from({ length: argc }, (_, i) => this.memory.read32(esp + 4 + i * 4));
    const result = this.invoke(entry, args);
    const key = `${entry.dll}!${entry.api}`;
    this.used.set(key, (this.used.get(key) ?? 0) + 1);
    cpu.regs[0] = result >>> 0;
    // stdcall: pop return address and arguments; caller-owned scratch stays intact.
    cpu.ret(32, argc * 4);
  }
}
