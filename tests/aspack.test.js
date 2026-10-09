import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { Bytes, MAX_OUTPUT } from '../src/core/bytes.js';
import { parsePE } from '../src/core/pe.js';
import { ASPACK_ENGINE, supportsAspack, unpackAspack, decodeAspackBlock } from '../src/core/unpackers/aspack.js';
const root = new URL('../test-results/fixtures/aspack/', import.meta.url);
let packed, golden;
try { packed = new Uint8Array(await readFile(new URL('aspack-lbop20.bin', root))); golden = new Uint8Array(await readFile(new URL('golden-lbop20.bin', root))); } catch {}
const options = { skip: !packed || !golden ? 'run node scripts/fetch-aspack-fixtures.mjs for pinned independent corpus' : false };
const sha = b => createHash('sha256').update(b).digest('hex');
const mutate32 = (at, value) => { const copy = packed.slice(); new Bytes(copy).put32(at, value); return copy; };
const comparableImports = pe => pe.imports.map(m => ({ name: m.name.toLowerCase(), firstThunk: m.firstThunk,
  functions: m.functions.map(f => f.name ?? `#${f.ordinal}`) })).sort((a,b) => a.name.localeCompare(b.name));

test('ASPack fixture and independent golden hashes are pinned', options, () => {
  assert.equal(sha(packed), 'a7a2f792185842ea20f100f8a0059842bc299a2e5c0318751840fdd38224800a');
  assert.equal(sha(golden), '4de460a6f7658f9c6233c9be3f9be70cf893d2010276c1b5c7521cfc42e15ce7');
});
test('ASPack exact EP437 build closes five blocks against independent golden', options, () => {
  const result = unpackAspack(packed), pe = parsePE(result.bytes, MAX_OUTPUT), gp = parsePE(golden);
  assert.equal(supportsAspack(packed), true); assert.equal(result.metadata.engine, ASPACK_ENGINE.id);
  // Per-sample grading (T38): every carried directory is either the packed
  // header's own record re-validated against the decoded image or rebuilt
  // from strict structural evidence, so this sample upgrades to rebuilt-pe.
  assert.equal(result.metadata.outputKind, 'rebuilt-pe'); assert.equal(result.metadata.runtimeVerified, false);
  assert.equal(pe.entryPointRva, 0x1252); assert.deepEqual(pe.warnings, []); assert.equal(pe.sections.length, 6);
  assert.deepEqual(comparableImports(pe), comparableImports(gp));
  assert.equal(result.metadata.importedFunctions, 64);
  const iats = gp.imports.map(m => ({ start: m.firstThunk, end: m.firstThunk + (m.functions.length+1)*4 }));
  // The published oracle also relocates its ILT/name pointers in the original
  // descriptor array; import semantics are independently compared above.
  iats.push({start:pe.directories[1].rva,end:pe.directories[1].rva+pe.directories[1].size});
  let verified = 0;
  for (const block of result.metadata.decodedBlocks) {
    const a=pe.rvaToOffset(block.rva,block.size), b=gp.rvaToOffset(block.rva,block.size);
    for(let i=0;i<block.size;i++) {
      if(iats.some(v => block.rva+i>=v.start && block.rva+i<v.end)) continue;
      assert.equal(result.bytes[a+i],golden[b+i], `RVA ${(block.rva+i).toString(16)}`); verified++;
    }
  }
  assert.equal(verified, 74844); // Exclude only IAT slots and the rebuilt descriptor array.
});
test('ASPack lbop20 directory restoration is golden-verified per directory', options, () => {
  // Resource: the packed header records dir2 = 0x15000/0x1e0; the decoded tree
  // equals the golden dump's tree byte for byte. Its single leaf (RT_MANIFEST
  // id 24/1/1033) points at 0x18080/0x17d — ASPack shrank .rsrc to the tree
  // and re-hosted the data verbatim inside .aspack at the same RVA (bytes are
  // identical across this packed file, the ASPack golden dump and the same
  // original program's UPX golden leaf). The engine rescues those bytes from
  // the packed file into a derived .rsdata section covering exactly the
  // aligned leaf extent — no other layout is invented.
  const result = unpackAspack(packed), pe = parsePE(result.bytes, MAX_OUTPUT), gp = parsePE(golden);
  assert.deepEqual(result.metadata.restoredDirectories, { resource: 'restored', relocation: 'restored' });
  assert.equal(result.metadata.relocationSource, 'reloc-section-walk');
  assert.deepEqual(result.metadata.resourceDataSection, { rva: 0x18000, virtualSize: 0x1000 });
  assert.equal(pe.directories[2].rva, gp.directories[2].rva); assert.equal(pe.directories[2].size, gp.directories[2].size);
  const tree = pe.rvaToOffset(0x15000), manifest = pe.rvaToOffset(0x18080);
  assert.equal(Buffer.compare(Buffer.from(result.bytes.subarray(tree, tree + 0x1e0)), Buffer.from(golden.subarray(0x15000, 0x15000 + 0x1e0))), 0);
  assert.equal(Buffer.compare(Buffer.from(result.bytes.subarray(manifest, manifest + 0x17d)), Buffer.from(golden.subarray(0x18080, 0x18080 + 0x17d))), 0);
  const rsdata = pe.sections[5];
  assert.equal(rsdata.name, '.rsdata'); assert.equal(rsdata.rva, 0x18000); assert.equal(rsdata.virtualSize, 0x1000);
  // Relocation: the packed header's dir5 points at the stub's own 8-byte block
  // (0x17fc8, unmappable once the stub sections are dropped). The original
  // table survives decoded in .reloc: a strict block walk recovers
  // {0x16000, 0xdc0} — 19 blocks / 1676 HIGHLOW entries / all-zero tail, byte-
  // identical to the golden dump's .reloc section (3520/3520) and matching the
  // same original program's relocation count under UPX (docs/research/
  // rlde-family.md §12).
  assert.equal(pe.directories[5].rva, 0x16000); assert.equal(pe.directories[5].size, 0xdc0);
  const reloc = pe.rvaToOffset(0x16000);
  assert.equal(Buffer.compare(Buffer.from(result.bytes.subarray(reloc, reloc + 0xdc0)), Buffer.from(golden.subarray(0x16000, 0x16000 + 0xdc0))), 0);
});
test('ASPack OEP hand-off frame is cross-validated against the RL!deASPack probe site', options, () => {
  // RL!deASPack 2.x locates the OEP transfer with the probe `c2 0c 00 68`
  // (`ret 0xc; push`) and reads the transfer immediate at run time. In the
  // ep437 generation that frame is the anchored ep+0x417 sequence: the OEP
  // rides in `mov eax,<imm32>` at ep+0x418, and the probe bytes sit at
  // ep+0x434 — exactly one file-wide occurrence each (docs/research/
  // rlde-family.md §13a, MT29 evidence 资料/reverse/mt27-rlde-aspack*).
  const pe = parsePE(packed), ep = pe.entryPointOffset, view = new Bytes(packed);
  assert.deepEqual(Array.from(packed.subarray(ep + 0x434, ep + 0x438)), [0xc2, 0x0c, 0x00, 0x68]);
  let probeHits = 0, oepHits = 0;
  for (let at = 0; at + 4 <= packed.length; at++) {
    if (packed[at] === 0xc2 && packed[at + 1] === 0x0c && !packed[at + 2] && packed[at + 3] === 0x68) probeHits++;
    if (view.u32(at) === 0x1252) oepHits++;
  }
  assert.equal(probeHits, 1); assert.equal(oepHits, 1); assert.equal(view.u32(ep + 0x418), 0x1252);
  assert.equal(unpackAspack(packed).metadata.originalEntryPoint, parsePE(golden).entryPointRva);
});
test('ASPack directory grading downgrades per sample with specific warnings', options, () => {
  const pe = parsePE(packed);
  // A recorded resource directory whose mapped bytes are not a valid tree
  // keeps the sample at analysis-pe; the relocation verdict is independent.
  const badTree = mutate32(pe.directoryOffset + 16, 0x1000);
  const down = unpackAspack(badTree), downPe = parsePE(down.bytes, MAX_OUTPUT);
  assert.equal(down.metadata.outputKind, 'analysis-pe');
  assert.equal(down.metadata.restoredDirectories.resource, 'not-restored');
  assert.equal(down.metadata.restoredDirectories.relocation, 'restored');
  assert.ok(down.metadata.warnings.includes('resources-not-restorable'));
  assert.ok(down.metadata.warnings.includes('analysis-only-not-runnable'));
  assert.equal(downPe.directories[2].rva, 0); assert.equal(downPe.directories[2].size, 0);
  assert.equal(downPe.directories[5].rva, 0x16000); assert.equal(downPe.directories[5].size, 0xdc0);
  // Renaming .reloc removes the only relocation evidence (the header record
  // points at the removed stub): honest downgrade, resource unaffected.
  const reloc = pe.sections.find(s => s.name === '.reloc');
  assert.ok(reloc); const renamed = packed.slice(); renamed[reloc.headerOffset + 1] ^= 1;
  const down2 = unpackAspack(renamed), downPe2 = parsePE(down2.bytes, MAX_OUTPUT);
  assert.equal(down2.metadata.outputKind, 'analysis-pe');
  assert.equal(down2.metadata.restoredDirectories.relocation, 'not-restored');
  assert.equal(down2.metadata.restoredDirectories.resource, 'restored');
  assert.ok(down2.metadata.warnings.includes('relocations-not-restorable'));
  assert.equal(downPe2.directories[5].rva, 0); assert.equal(downPe2.sections.length, 6);
  // A header with no resource record at all is the absent normal state, not a
  // failure: the sample stays rebuilt-pe and nothing is synthesized.
  const noRes = packed.slice(); new Bytes(noRes).put32(pe.directoryOffset + 16, 0); new Bytes(noRes).put32(pe.directoryOffset + 20, 0);
  const clean = unpackAspack(noRes), cleanPe = parsePE(clean.bytes, MAX_OUTPUT);
  assert.equal(clean.metadata.outputKind, 'rebuilt-pe');
  assert.equal(clean.metadata.restoredDirectories.resource, 'absent');
  assert.equal(clean.metadata.resourceDataSection, undefined);
  assert.equal(cleanPe.directories[2].rva, 0); assert.equal(cleanPe.sections.length, 5);
});
test('ASPack streams require real input bytes, never zero-padded truncation', options, () => {
  const table = packed.slice(0x9f4a,0x9fbc), stream = packed.subarray(0x400,0x400+24891);
  for(const n of [0,1,4,32,512,24890]) assert.throws(() => decodeAspackBlock(stream.subarray(0,n),45568,table));
  assert.equal(decodeAspackBlock(stream,45568,table).consumed,24891);
});
test('ASPack signature, constant table and arithmetic table reference mutations are refused', options, () => {
  for(const at of [0x9801,0x98ad,0x9908,0x994b,0x9f4a,0xa2b6,0xa513]) {
    const copy=packed.slice(); copy[at]^=1; assert.equal(supportsAspack(copy),false,at.toString(16)); assert.throws(()=>unpackAspack(copy));
  }
});
test('ASPack bad or overlapping block descriptors are refused', options, () => {
  for(const [at,value] of [[0x9df0,0x17000],[0x9df4,0xffffffff],[0x9df8,0],[0x9dfc,0x1000],[0x9e2c,0x1000]]) {
    const copy=mutate32(at,value); assert.equal(supportsAspack(copy),false); assert.throws(()=>unpackAspack(copy));
  }
});
test('ASPack wrong OEP, import directory and PE shape cannot be upgraded', options, () => {
  const pe=parsePE(packed);
  for(const [at,value] of [[0x9c19,0x17001],[0x9a7d,0x17000],[pe.optionalOffset+56,MAX_OUTPUT+4096],[pe.optionalOffset+32,0x200]]) assert.throws(()=>unpackAspack(mutate32(at,value)));
  const copy=packed.slice(); new Bytes(copy).put16(pe.peOffset+4,0x8664); assert.equal(supportsAspack(copy),false);
});
test('ASPack old entry anchors and section-only lookalikes stay unsupported', options, () => {
  const copy=packed.slice(); copy[0x9802]=0xe9; assert.equal(supportsAspack(copy),false); assert.throws(()=>unpackAspack(copy));
  assert.equal(supportsAspack(new Uint8Array(512)),false); assert.equal(supportsAspack(golden),false);
});
test('ASPack overlay is excluded and results do not alias input or prior output', options, () => {
  const extended=new Uint8Array(packed.length+16); extended.set(packed); extended.fill(0xa5,packed.length);
  const original=sha(packed), a=unpackAspack(packed), b=unpackAspack(extended);
  assert.deepEqual(a.bytes,b.bytes); assert.ok(b.metadata.warnings.includes('overlay-not-preserved'));
  a.bytes.fill(0); assert.equal(sha(packed),original); assert.notEqual(sha(b.bytes),sha(a.bytes));
});
test('ASPack bounded Huffman malformed inputs fail without partial PE', () => {
  const table=new Uint8Array(114);
  for(let i=0;i<128;i++) {
    const input=Uint8Array.from({length:48},(_,j)=>(i*29+j*71)&255);
    assert.throws(()=>decodeAspackBlock(input,64,table));
  }
  assert.throws(()=>decodeAspackBlock(new Uint8Array(4),MAX_OUTPUT+1,table));
  assert.throws(()=>decodeAspackBlock(new Uint8Array(4),4,new Uint8Array(113)));
});
