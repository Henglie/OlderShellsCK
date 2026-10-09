import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { Script } from 'node:vm';
import { detect, DIE_SCOPE } from '../src/core/detect.js';
import data from '../vendor/die/entry-patterns.json' with { type: 'json' };

test('additional direct-entry branches agree with the original pinned DIE script metadata', async () => {
  assert.deepEqual(data.map(rule => [rule.family, rule.patterns.length]), [
    ['ASPack', 14], ['Petite', 11], ['MEW', 4], ['PECompact', 8], ['RLPack', 2], ['tElock', 5], ['PELock', 1], ['NsPack', 6], ['WinUpack', 10],
  ]);
  for (const rule of data) {
    const source = await readFile(new URL(`../vendor/die/${rule.source}`, import.meta.url), 'utf8');
    const script = new Script(source + '\ndetect();');
    for (const pattern of rule.patterns) {
      const bytes = new Uint8Array(1024), ep = 512;
      bytes.set(Buffer.from(pattern.pattern.replaceAll('..', 'a5'), 'hex'), ep);
      const match = (value, offset = ep) => /^[a-f\d.]+$/i.test(value) && new RegExp(`^${value}`, 'i').test(Buffer.from(bytes.subarray(offset)).toString('hex'));
      // Stub host surface covers every helper any pinned script may call on
      // the non-matching paths; entry hits must come from the EP pattern.
      const context = { sVersion: '', sOptions: '', bDetected: false, meta() {}, result() {}, X: { isVerbose: () => false }, PE: {
        compareEP: (value, delta = 0) => match(value, ep + delta), compare: match, getEntryPointOffset: () => ep,
        findString: () => -1, isNet: () => false, is64: () => false, section: {},
        getNumberOfImportThunks: () => 0, getNumberOfImports: () => 0, getSizeOfCode: () => 1,
        getImportFunctionName: () => '', getImportLibraryName: () => '', isLibraryPresent: () => false,
        isImportPositionHashPresent: () => false, isNetObjectPresent: () => false, isSectionNamePresent: () => false,
        readByte: () => 0, readWord: () => 0, readDword: () => 0,
        OffsetToVA: offset => 0x400000 + offset, getDisasmString: () => '', getDisasmNextAddress: address => address,
      } };
      script.runInNewContext(context, { timeout: 100 });
      assert.equal(context.bDetected, true, `${rule.family} source branch`);
      const pe = { machine: 0x14c, is64: false, isNet: false, entryPointOffset: ep, entryPointRva: 0x1000, sections: [], rvaToOffset: (rva, length) => rva >= 0x1000 && rva + length <= 0x1200 ? ep + rva - 0x1000 : null };
      const hit = detect(bytes, pe).find(hit => hit.family === rule.family);
      assert.ok(hit, `${rule.family} ${pattern.pattern}`);
      assert.equal(hit.version, context.sVersion);
      assert.equal(hit.evidence[0].options, context.sOptions);
      assert.equal(hit.source, 'die-rule-subset');
      if (rule.netExcluded) {
        pe.isNet = true;
        assert.equal(detect(bytes, pe).some(hit => hit.family === rule.family), false, 'netExcluded families skip .NET inputs');
        pe.isNet = false;
      }
      pe.rvaToOffset = () => null;
      assert.equal(detect(bytes, pe).some(hit => hit.family === rule.family), false, 'unmapped signatures rejected');
      pe.machine = 0xaa64;
      assert.equal(detect(bytes, pe).some(hit => hit.family === rule.family), false, 'x86 patterns never infer ARM64');
    }
  }
  assert.equal(DIE_SCOPE.families.length, 12);
  assert.equal(DIE_SCOPE.fullEngine, false);
});

test('local research probes fire on co-occurrence and stay gated', () => {
  const stub = { machine: 0x14c, is64: false, isNet: false, entryPointOffset: 512, entryPointRva: 0x1000, sections: [], rvaToOffset: () => null };
  const probeBytes = (...chunks) => {
    const bytes = new Uint8Array(0x1000);
    let offset = 0x40;
    for (const hex of chunks) {
      bytes.set(Buffer.from(hex, 'hex'), offset);
      offset += hex.length / 2 + 7;
    }
    return bytes;
  };
  const families = bytes => detect(bytes, stub);

  // tElock: two distinct transform constants fire; a single one never does.
  const telock = probeBytes('81ef195f322a', '81f64d15a56d');
  const telockHit = families(telock).find(hit => hit.family === 'tElock');
  assert.equal(telockHit.source, 'local-research-mt29');
  assert.deepEqual(telockHit.evidence[0].probes.map(probe => probe.pattern).sort(), ['81ef195f322a', '81f64d15a56d']);
  assert.equal(families(probeBytes('81ef195f322a')).some(hit => hit.family === 'tElock'), false);

  // ASPack: OEP handoff probe plus one companion; handoff alone never fires.
  assert.equal(families(probeBytes('c20c0068', 'ff7f53ff')).some(hit => hit.family === 'ASPack'), true);
  assert.equal(families(probeBytes('c20c0068')).some(hit => hit.family === 'ASPack'), false);
  assert.equal(families(probeBytes('8b8850ff', '85db')).some(hit => hit.family === 'ASPack'), false);

  // FSG 2.0: both RL!de probes required; the DIE upstream EP branch wins when
  // it also matches (1.33 rule 668BC0... style stays on die-rule-subset).
  const fsgHit = families(probeBytes('ad50', 'ff630c50')).find(hit => hit.family === 'FSG');
  assert.equal(fsgHit.source, 'local-research-mt29');
  assert.equal(fsgHit.version, '2.0');
  assert.equal(families(probeBytes('ad50')).some(hit => hit.family === 'FSG'), false);

  // Gates: x86-only and non-.NET-only.
  stub.machine = 0x8664;
  assert.equal(families(probeBytes('c20c0068', '8b8850ff')).some(hit => hit.family === 'ASPack'), false);
  stub.machine = 0x14c;
  stub.isNet = true;
  assert.equal(families(probeBytes('c20c0068', '8b8850ff')).some(hit => hit.family === 'ASPack'), false);
  stub.isNet = false;

  const upstream = probeBytes();
  const ep = 512;
  const mapped = { ...stub, rvaToOffset: (rva, length) => rva >= 0x1000 && rva + length <= 0x1200 ? ep + rva - 0x1000 : null };
  upstream.set(Buffer.from('E90000000060E8000000005883C008', 'hex'), ep);
  upstream.set(Buffer.from('81ef195f322a', 'hex'), 0x800);
  upstream.set(Buffer.from('81c602b85502', 'hex'), 0x810);
  // With the EP mapped, the pinned DIE branch wins; without it the research
  // scan is the only evidence left.
  assert.equal(detect(upstream, mapped).find(hit => hit.family === 'tElock').source, 'die-rule-subset');
  assert.equal(detect(upstream, mapped).find(hit => hit.family === 'tElock').version, '0.60');
  assert.equal(families(upstream).find(hit => hit.family === 'tElock').source, 'local-research-mt29');

  // The 2 MiB scan window bounds cost: probes placed beyond it are invisible.
  const far = new Uint8Array(0x300000);
  far.set(Buffer.from('81ef195f322a', 'hex'), 0x200100);
  far.set(Buffer.from('81c602b85502', 'hex'), 0x200110);
  assert.equal(families(far).some(hit => hit.family === 'tElock'), false);
});
