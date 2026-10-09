import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { Bytes, MAX_OUTPUT } from '../src/core/bytes.js';
import { parsePE } from '../src/core/pe.js';
import { MEW_ENGINE, supportsMew, parseMewPE, unpackMew } from '../src/core/unpackers/mew.js';
let packed,golden;
try { packed=new Uint8Array(await readFile(new URL('../test-results/fixtures/mew/lbop20-mew.bin',import.meta.url)));
  golden=new Uint8Array(await readFile(new URL('../test-results/fixtures/aspack/golden-lbop20.bin',import.meta.url))); } catch {}
const options={skip:!packed||!golden?'fetch pinned MEW and ASPack same-program independent corpus':false};
const sha=b=>createHash('sha256').update(b).digest('hex');
const change=(at,value)=>{const b=packed.slice();new Bytes(b).put32(at,value);return b;};

test('MEW corpus and independent same-program ASPack golden are pinned',options,()=>{
  assert.equal(sha(packed),'42e83208184d5ef0ebfced4347540b4629fe2d6c901295dd0dc9eb18a5b96af5');
  assert.equal(sha(golden),'4de460a6f7658f9c6233c9be3f9be70cf893d2010276c1b5c7521cfc42e15ce7');
});
test('MEW exact adapter accepts overlapping DOS fields without weakening parsePE',options,()=>{
  assert.throws(()=>parsePE(packed),{code:'invalid-pe-header'}); const pe=parseMewPE(packed);
  assert.equal(pe.peOffset,0x0c); assert.equal(pe.entryPointOffset,0x8570); assert.equal(supportsMew(packed),true);
  assert.equal(pe.rvaToOffset(0x18000),0x200); assert.equal(pe.rvaToOffset(0x17000),null);
});
test('MEW restores code, OEP and all import slots against independently published golden',options,()=>{
  const result=unpackMew(packed),pe=parsePE(result.bytes,MAX_OUTPUT),gp=parsePE(golden);
  assert.equal(result.metadata.engine,MEW_ENGINE.id);assert.equal(result.metadata.outputKind,'rebuilt-pe');assert.equal(result.metadata.runtimeVerified,false);
  assert.equal(pe.entryPointRva,0x1252);assert.deepEqual(pe.warnings,[]);assert.equal(result.metadata.importedFunctions,64);
  assert.equal(result.metadata.loaderBlocks,2);assert.equal(result.metadata.decodedBlocks[0].size,75890);
  const a=pe.rvaToOffset(0x1000,45568),b=gp.rvaToOffset(0x1000,45568);
  assert.deepEqual(result.bytes.subarray(a,a+45568),golden.subarray(b,b+45568));
  for(const module of pe.imports){const gm=gp.imports.find(v=>v.name.toLowerCase()===module.name.toLowerCase());
    assert.ok(gm);assert.equal(module.firstThunk,gm.firstThunk);assert.deepEqual(module.functions.map(f=>f.name??f.ordinal),gm.functions.map(f=>f.name??f.ordinal));}
});
test('MEW output is a normalized rebuilt PE with directories 1/12 and disk-state IAT',options,()=>{
  const result=unpackMew(packed),pe=parsePE(result.bytes,MAX_OUTPUT),out=new Bytes(result.bytes);
  assert.equal(pe.peOffset,0x80);assert.deepEqual(pe.warnings,[]);
  assert.deepEqual(pe.sections.map(s=>s.name),['.mew','.idata']);
  const idata=pe.sections[1],slots=pe.imports.map(m=>({start:m.firstThunk,end:m.firstThunk+(m.functions.length+1)*4}));
  assert.equal(pe.directories[1].rva,idata.rva);assert.equal(pe.directories[1].size,(pe.imports.length+1)*20);
  assert.equal(pe.directories[12].rva,Math.min(...slots.map(v=>v.start)));
  assert.equal(pe.directories[12].size,Math.max(...slots.map(v=>v.end))-Math.min(...slots.map(v=>v.start)));
  for(const module of pe.imports)for(let j=0;j<=module.functions.length;j++){
    const slot=out.u32(pe.rvaToOffset(module.firstThunk+j*4));
    assert.ok(slot===0||(slot>=idata.rva&&slot<idata.rva+idata.virtualSize)||(slot&0x80000000)===0x80000000,module.firstThunk.toString(16)+':'+j.toString());
  }
});
test('MEW LZMA payload is byte-exact against independent liblzma raw decoding',options,t=>{
  let expected;
  try{expected=Buffer.from(execFileSync('py',['-3.11','-B','-c',
    "import lzma,sys; d=bytes.fromhex(sys.stdin.read()); z=lzma.LZMADecompressor(format=lzma.FORMAT_RAW,filters=[{'id':lzma.FILTER_LZMA1,'dict_size':94208,'lc':4,'lp':0,'pb':2}]); print(z.decompress(d,max_length=75890).hex())"],{input:Buffer.from(packed.subarray(0x8cf,0x8cf+31856)).toString('hex'),encoding:'utf8',timeout:15000,maxBuffer:1024*1024}).trim(),'hex');}
  catch(error){t.skip(`independent Python/liblzma oracle unavailable: ${error.code}`);return;}
  const result=unpackMew(packed),pe=parsePE(result.bytes),start=pe.rvaToOffset(0x1000),gp=parsePE(golden);
  const iats=gp.imports.map(m=>({start:m.firstThunk-0x1000,end:m.firstThunk-0x1000+(m.functions.length+1)*4}));
  assert.equal(expected.length,75890);
  for(let i=0;i<expected.length;i++)if(!iats.some(v=>i>=v.start&&i<v.end))assert.equal(result.bytes[start+i],expected[i],i.toString(16));
});
test('MEW full loader, scattered bit reader and helper references are exact',options,()=>{
  for(const at of [0x108,0x12c,0x154,0x170,0x200,0x21c,0x8570]){const b=packed.slice();b[at]^=1;assert.equal(supportsMew(b),false,at.toString(16));assert.throws(()=>unpackMew(b));}
});
test('MEW bad support, OEP, destination and declared image budgets are refused',options,()=>{
  for(const [at,value]of[[0x155,0xffffffff],[0x224,0x420000],[0x220,0x420000],[0x13c,0xffffffff],[0x5c,MAX_OUTPUT+4096]])assert.throws(()=>unpackMew(change(at,value)));
});
test('MEW damaged LZMA size, initializer, final state and import pointer are refused',options,()=>{
  for(const [at,value]of[[0x8c2,0xffffffff],[0x8c6,0x418000],[0x8ca,31855],[0x8cf,0xffffffff],[0x8543,0x400100]])assert.throws(()=>unpackMew(change(at,value)),undefined,at.toString(16));
  const copy=packed.slice();copy[0x853e]^=1;assert.throws(()=>unpackMew(copy));
});
test('MEW non-SE, MEW10 and unrelated files remain unsupported',options,()=>{
  const nonSE=packed.slice();nonSE[0x1cf]=0x90;assert.equal(supportsMew(nonSE),false);
  const mew10=packed.slice();mew10[0x159]=0xac;mew10[0x15a]=0x91;assert.equal(supportsMew(mew10),false);
  assert.equal(supportsMew(golden),false);assert.equal(supportsMew(new Uint8Array(512)),false);
});
test('MEW truncated files cannot borrow bytes from headers or appended overlay',options,()=>{
  for(const n of [0,64,511,0x200,0x1000,packed.length-1])assert.throws(()=>unpackMew(packed.subarray(0,n)));
  const copy=packed.slice();new Bytes(copy).put32(0x8571,0x100);assert.equal(supportsMew(copy),false);
});
test('MEW input/subviews are immutable and output storage is isolated',options,()=>{
  const container=new Uint8Array(packed.length+16).fill(0xcc);container.set(packed,5);const before=sha(container);
  const a=unpackMew(container.subarray(5,5+packed.length)),b=unpackMew(packed);assert.deepEqual(a.bytes,b.bytes);
  a.bytes.fill(0);assert.equal(sha(container),before);assert.notEqual(sha(a.bytes),sha(b.bytes));
});
