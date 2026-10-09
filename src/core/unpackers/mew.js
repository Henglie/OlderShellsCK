// MEW framing adapted from XStaticUnpacker xmew.cpp (MIT).
// Copyright (c) 2017-2026 hors<horsicq@gmail.com>
// Revision 746fb24433c29b6460edebac83fdad19909d9e81.
// See licenses/xstaticunpacker-MIT.txt and docs/research/rlde-family.md.
import { Bytes, MAX_INPUT, MAX_OUTPUT, align, entropy, matchHex } from '../bytes.js';
import { requireThat } from '../errors.js';
import { parsePE } from '../pe.js';
import { decompressFsg } from '../codecs/fsg.js';
import { decodeLzma1 } from '../compression/lzma.js';

export const MEW_ENGINE = Object.freeze({
  id: 'mew-pe32-lzma1', family: 'mew', catalogId: 'mew', variants: Object.freeze(['11-SE-154']),
  outputKind: 'rebuilt-pe', runtimeVerified: false, stage: 'experimental',
});
const STUB = 'be........8bdeadad50ad97b280a4b680ff1373f933c9ff13731633c0ff137321b68041b010ff1312c073fa753eaaebe0e8........02f683d901750eff53fceb26acd1e8742f13c9eb1a9148c1e008acff53fc3d007d0000730a80fc05730683f87f77024141958bc5b600568bf72bf0f3a45eeb9bad85c07590e8........ad96ad9756ac3c0075fbff53f09556ad0fc8405974ec7907ac3c0075fb91405055ff53f4ab85c075e5c3';

function inspect(bytes) {
  requireThat(bytes instanceof Uint8Array, 'invalid-input');
  requireThat(bytes.length > 0 && bytes.length <= MAX_INPUT, 'input-size-limit');
  const r = new Bytes(bytes); requireThat(r.u16(0) === 0x5a4d, 'not-pe');
  const peOffset = r.u32(0x3c);
  requireThat(peOffset === 0x0c, 'unsupported-variant');
  requireThat(r.u32(peOffset) === 0x4550, 'not-pe');
  const optionalOffset = peOffset + 24, directoryOffset = optionalOffset + 96, sectionTable = optionalOffset + 0xe0;
  requireThat(r.u16(peOffset + 4) === 0x14c && r.u16(peOffset + 6) === 2 && r.u16(peOffset + 20) === 0xe0 &&
    !(r.u16(peOffset + 22) & 0x2000) && r.u16(optionalOffset) === 0x10b, 'unsupported-variant');
  r.range(sectionTable, 80);
  requireThat(r.u32(directoryOffset - 4) === 16, 'unsupported-directories');
  const directories = Array.from({ length: 16 }, (_, i) => ({ rva: r.u32(directoryOffset + i * 8), size: r.u32(directoryOffset + i * 8 + 4) }));
  requireThat(!directories[9].rva && !directories[13].rva && !directories[14].rva, 'unsupported-directories');
  const base = r.u32(optionalOffset + 28), sizeOfImage = r.u32(optionalOffset + 56), sizeOfHeaders = r.u32(optionalOffset + 60);
  requireThat(r.u32(optionalOffset + 32) === 0x1000 && r.u32(optionalOffset + 36) === 0x200, 'unsupported-alignment');
  requireThat(sizeOfImage > 0 && sizeOfImage <= MAX_OUTPUT && sizeOfImage % 0x1000 === 0 && base % 0x10000 === 0 && base + sizeOfImage <= 0x100000000, 'output-size-limit');
  requireThat(sizeOfHeaders === 0x200 && sectionTable + 80 === 0x154, 'unsupported-mew-layout');
  const sections = Array.from({ length: 2 }, (_, i) => {
    const h = sectionTable + i * 40;
    return { name: r.string(h, 8), headerOffset: h, virtualSize: r.u32(h + 8), rva: r.u32(h + 12),
      rawSize: r.u32(h + 16), rawOffset: r.u32(h + 20), characteristics: r.u32(h + 36) };
  });
  const [destination, source] = sections;
  requireThat(destination.rva === 0x1000 && destination.rawSize === 0 && destination.rawOffset === 0 &&
    destination.virtualSize > 0 && destination.virtualSize % 0x1000 === 0 && source.rva === destination.rva + destination.virtualSize &&
    source.rawOffset === 0x200 && source.rawSize > 0 && source.rawSize <= source.virtualSize &&
    source.virtualSize > 0 && source.rva + source.virtualSize <= sizeOfImage, 'unsupported-mew-layout');
  r.range(source.rawOffset, source.rawSize);
  const entryPointRva = r.u32(optionalOffset + 16), entryPointOffset = source.rawOffset + entryPointRva - source.rva;
  requireThat(entryPointRva >= source.rva && entryPointRva + 5 <= source.rva + source.rawSize && r.u8(entryPointOffset) === 0xe9 &&
    entryPointRva + 5 + r.i32(entryPointOffset + 1) === 0x154, 'unsupported-variant');
  requireThat(matchHex(bytes, 0x154, STUB), 'unsupported-variant');
  const headerRva = r.u32(0x155) - base, header = headerRva - source.rva;
  requireThat(header >= 16 && header + 12 <= source.rawSize && header < 0x200 - 4, 'invalid-mew-support');
  const at = source.rawOffset + header, originalEntryPoint = r.u32(at + 4) - base, firstDestination = r.u32(at + 8) - base;
  requireThat(originalEntryPoint >= destination.rva && originalEntryPoint < source.rva, 'invalid-original-entry');
  requireThat(firstDestination >= destination.rva && firstDestination < source.rva + source.virtualSize, 'invalid-mew-destination');
  const lzmaRva = 0x154 + 0x80 + r.i32(0x154 + 0x7c);
  const helperRva = 0x154 + 0x36 + r.i32(0x154 + 0x32);
  requireThat(helperRva === source.rva && lzmaRva >= source.rva + source.rawSize && lzmaRva < source.rva + source.virtualSize, 'unsupported-variant');
  // Function pointers and gamma/bit helpers are data evidence, never invoked.
  requireThat(r.u32(at) - base === 0x12c && r.u32(at - 4) - base === helperRva &&
    matchHex(bytes,0x12c,'02d275db8a16ebd4') && matchHex(bytes,0x108,'4612d2c3') &&
    matchHex(bytes,source.rawOffset,'33c941ff1313c9ff1372f8c3'), 'invalid-mew-support');
  const rvaToOffset = (rva, length = 1) => {
    if (!Number.isSafeInteger(rva) || !Number.isSafeInteger(length) || rva < 0 || length < 0) return null;
    if (rva + Math.max(1,length) <= 0x200) return rva;
    const delta = rva - source.rva;
    return delta >= 0 && delta + Math.max(1,length) <= source.rawSize ? source.rawOffset + delta : null;
  };
  const pe = { format: 'PE32', architecture: 'x86', machine: 0x14c, is64: false, isDll: false, isNet: false,
    peOffset, optionalOffset, directoryOffset, sectionTable, sizeOfImage, sizeOfHeaders, fileAlignment: 0x200, sectionAlignment: 0x1000,
    imageBase: `0x${base.toString(16)}`, entryPointRva, entryPointOffset, sections, directories, imports: [],
    overlay: { offset: source.rawOffset + source.rawSize, size: bytes.length - source.rawOffset - source.rawSize },
    warnings: ['mew-overlapping-dos-header'], rvaToOffset };
  return { pe, header, originalEntryPoint, firstDestination, lzmaRva };
}

// Exact MEW-only fallback; the generic parsePE remains strict.
export function parseMewPE(bytes) {
  const { pe } = inspect(bytes);
  for (const s of pe.sections) s.entropy = entropy(bytes.subarray(s.rawOffset,s.rawOffset+s.rawSize));
  return pe;
}
export function supportsMew(bytes, pe) {
  try { if (pe && (pe.machine !== 0x14c || pe.is64 || pe.isDll || pe.isNet)) return false; inspect(bytes); return true; } catch { return false; }
}

export function unpackMew(bytes) {
  const plan = inspect(bytes), { pe, originalEntryPoint } = plan, [destination, source] = pe.sections;
  const base = Number(pe.imageBase), image = new Uint8Array(destination.virtualSize + source.virtualSize), m = new Bytes(image);
  image.set(bytes.subarray(source.rawOffset,source.rawOffset+source.rawSize),destination.virtualSize);
  const vaToOffset = va => { requireThat(va >= base + destination.rva && va < base + destination.rva + image.length, 'invalid-mew-pointer'); return va - base - destination.rva; };
  let cursor = destination.virtualSize + plan.header + 12, target = plan.firstDestination - destination.rva;
  const sourceEnd = destination.virtualSize + source.rawSize, loaders = [];
  for (let count = 0; ; count++) {
    requireThat(count < 64 && cursor < sourceEnd, 'mew-block-limit');
    const clear = decompressFsg(image.subarray(cursor,sourceEnd), image.length - target);
    const nextAt = cursor + clear.consumed;
    // A loader may occupy zero-fill above the file-backed source. It must not
    // overwrite its unread stream/container or any earlier loader.
    requireThat((target + clear.bytes.length <= destination.virtualSize || target >= sourceEnd) &&
      !loaders.some(v => target < v.end && v.start < target + clear.bytes.length), 'invalid-mew-destination');
    image.set(clear.bytes,target); loaders.push({ start: target, end: target + clear.bytes.length, consumed: clear.consumed });
    requireThat(nextAt + 4 <= sourceEnd, 'truncated-input');
    const next = m.u32(nextAt); cursor = nextAt + 4;
    if (!next) break;
    target = vaToOffset(next);
  }
  const lzma = plan.lzmaRva - destination.rva;
  requireThat(loaders.some(v => lzma >= v.start && lzma + 12 <= v.end) &&
    matchHex(image,lzma,'558bec83ec4053ad8945d889'), 'unsupported-mew-lzma-stub');
  // Only the observed zero-terminated block-list shape is accepted. Special
  // BCJ mode and non-SE/MEW10 are separate, unvalidated variants.
  requireThat(cursor + 4 <= sourceEnd, 'truncated-input');
  vaToOffset(m.u32(cursor)); cursor += 4;
  const decodedBlocks = [];
  for (let count = 0; ; count++) {
    requireThat(count < 64 && cursor + 4 <= sourceEnd, 'mew-block-limit');
    const size = m.u32(cursor);
    if (!size) { cursor += 4; break; }
    requireThat(cursor + 13 <= sourceEnd, 'truncated-input');
    const target = vaToOffset(m.u32(cursor+4)), packedSize = m.u32(cursor+8);
    requireThat(size > 0 && size <= destination.virtualSize - target && packedSize >= 5 && cursor + 13 + packedSize <= sourceEnd, 'invalid-mew-lzma-block');
    requireThat(!decodedBlocks.some(v => target < v.end && v.start < target + size) &&
      !loaders.some(v => target < v.end && v.start < target + size), 'invalid-mew-destination');
    requireThat(m.u8(cursor+12) === 0, 'unsupported-mew-lzma-framing');
    cursor += 13;
    const clear = decodeLzma1(image.subarray(cursor,cursor+packedSize),size,{ props:0x5e,dictionarySize:destination.virtualSize });
    requireThat(clear.consumed === packedSize && !clear.endMarker, 'invalid-mew-lzma-framing');
    image.set(clear.bytes,target); decodedBlocks.push({ start:target,end:target+size,size,compressedSize:packedSize }); cursor += packedSize;
  }
  requireThat(decodedBlocks.length > 0 && decodedBlocks.some(v => originalEntryPoint - destination.rva >= v.start && originalEntryPoint - destination.rva < v.end), 'invalid-original-entry');
  requireThat(cursor+4 <= sourceEnd, 'invalid-import-hints');
  const hints = vaToOffset(m.u32(cursor)), host = loaders.find(v => hints >= v.start && hints < v.end);
  requireThat(host !== undefined, 'invalid-import-hints');
  let at = hints, total = 0, ended = false; const modules = [], iats = [];
  const string = () => {
    requireThat(at < host.end, 'invalid-import-hints'); const value = m.cstring(at,512);
    requireThat(value.length && /^[\x21-\x7e]+$/.test(value) && at+value.length+1 <= host.end, 'invalid-import-hints');
    at += value.length+1; return value;
  };
  for (let i=0;i<256;i++) {
    requireThat(at+4 <= host.end, 'invalid-import-hints'); const pointer = m.u32(at); at += 4;
    if (!pointer) { ended = true; break; }
    const firstThunk = pointer-base, name = string(), functions = []; let last = false;
    for (let j=0;j<4096;j++) {
      // The final tag is an empty name in loader zero-fill: the packed aPLib
      // blob contains only 0x80, not four readable bytes or a second DLL.
      if(at===host.end-1 && image[at]===0x80) { at++; last=true; ended=true; break; }
      requireThat(at+4 <= host.end, 'invalid-import-hints');
      const be = ((image[at]*0x1000000)+(image[at+1]<<16)+(image[at+2]<<8)+image[at+3]) >>> 0;
      if (be===0xffffffff) { at+=4; last=true; break; }
      requireThat(++total<=16384, 'import-limit');
      if (image[at]===0x80) { at++; functions.push({name:string()}); }
      else { requireThat(be < 0xffff, 'invalid-import-hints'); functions.push({ordinal:be+1}); at+=4; }
    }
    const end = firstThunk+(functions.length+1)*4;
    requireThat(last && functions.length && firstThunk%4===0 && firstThunk>=destination.rva && end<=source.rva &&
      !iats.some(v => firstThunk<v.end && v.start<end), 'invalid-import-hints');
    iats.push({start:firstThunk,end}); modules.push({name,firstThunk,functions});
    if(ended) break;
  }
  requireThat(ended && modules.length>0 && at===host.end, 'invalid-import-hints');
  let importSize=(modules.length+1)*20;
  for(const mod of modules) {
    mod.nameOffset=importSize; importSize+=mod.name.length+1; importSize=align(importSize,4);
    mod.iltOffset=importSize; importSize+=(mod.functions.length+1)*4;
    for(const fn of mod.functions) if(fn.name) { importSize=align(importSize,2); fn.nameOffset=importSize; importSize+=fn.name.length+3; }
  }
  requireThat(importSize<=4*1024*1024,'import-limit');
  const payload=new Uint8Array(importSize), imp=new Bytes(payload), text=new TextEncoder();
  for(const [i,mod] of modules.entries()) {
    imp.put32(i*20,source.rva+mod.iltOffset); imp.put32(i*20+12,source.rva+mod.nameOffset); imp.put32(i*20+16,mod.firstThunk);
    payload.set(text.encode(mod.name),mod.nameOffset);
    for(const [j,fn] of mod.functions.entries()) {
      const value=fn.ordinal!==undefined?(0x80000000|fn.ordinal)>>>0:source.rva+fn.nameOffset;
      imp.put32(mod.iltOffset+j*4,value); m.put32(mod.firstThunk-destination.rva+j*4,value);
      if(fn.name) payload.set(text.encode(fn.name),fn.nameOffset+2);
    }
    m.put32(mod.firstThunk-destination.rva+mod.functions.length*4,0);
  }
  const optional=0x98, table=optional+0xe0, headers=0x200;
  const raw1=destination.virtualSize, raw2=align(importSize,0x200), size=headers+raw1+raw2;
  requireThat(size<=MAX_OUTPUT,'output-size-limit');
  const output=new Uint8Array(size), out=new Bytes(output);
  out.put16(0,0x5a4d); out.put32(0x3c,0x80); out.put32(0x80,0x4550); out.put16(0x84,0x14c); out.put16(0x86,2);
  out.put16(0x94,0xe0); out.put16(0x96,0x010f); out.put16(optional,0x10b);
  out.put32(optional+4,raw1); out.put32(optional+8,raw2); out.put32(optional+16,originalEntryPoint); out.put32(optional+20,destination.rva);
  out.put32(optional+28,base); out.put32(optional+32,0x1000); out.put32(optional+36,0x200);
  out.put16(optional+40,4); out.put16(optional+48,4); out.put32(optional+56,align(source.rva+importSize,0x1000)); out.put32(optional+60,headers);
  out.put16(optional+68,new Bytes(bytes).u16(pe.optionalOffset+68));
  out.put32(optional+72,0x100000); out.put32(optional+76,0x1000); out.put32(optional+80,0x100000); out.put32(optional+84,0x1000); out.put32(optional+92,16);
  out.put32(optional+104,source.rva); out.put32(optional+108,(modules.length+1)*20);
  const iatStart=Math.min(...iats.map(v=>v.start)),iatEnd=Math.max(...iats.map(v=>v.end));
  out.put32(optional+96+12*8,iatStart); out.put32(optional+100+12*8,iatEnd-iatStart);
  for(const [i,s] of [{name:'.mew',rva:destination.rva,size:destination.virtualSize,raw:headers,rawSize:raw1,flags:0xe0000060},
    {name:'.idata',rva:source.rva,size:importSize,raw:headers+raw1,rawSize:raw2,flags:0xc0000040}].entries()) {
    const h=table+i*40; output.set(text.encode(s.name),h); out.put32(h+8,s.size); out.put32(h+12,s.rva);
    out.put32(h+16,s.rawSize); out.put32(h+20,s.raw); out.put32(h+36,s.flags);
  }
  output.set(image.subarray(0,destination.virtualSize),headers); output.set(payload,headers+raw1);
  const result=parsePE(output,MAX_OUTPUT);
  requireThat(result.warnings.length===0 && result.entryPointOffset!==null && result.imports.length===modules.length &&
    result.imports.every((m,i)=>m.name===modules[i].name && m.functions.length===modules[i].functions.length &&
      m.functions.every((f,j)=>f.name===modules[i].functions[j].name && f.ordinal===modules[i].functions[j].ordinal)), 'output-validation-failed');
  return {bytes:output,metadata:{engine:MEW_ENGINE.id,variant:'11-SE-154',outputKind:'rebuilt-pe',runtimeVerified:false,
    originalEntryPoint,importsRebuilt:true,importedModules:modules.length,importedFunctions:total,decodedBlocks,loaderBlocks:loaders.length,
    warnings:['runtime-not-verified','original-headers-not-preserved','section-layout-and-permissions-inferred','resources-not-restored','relocations-not-restored',
      ...pe.warnings,...(pe.overlay.size?['overlay-not-preserved']:[])]}};
}
