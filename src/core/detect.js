// Selected Detect It Easy rules translated to bounded JS (MIT).
// Upstream authors: horsicq, ajax, adoxa, DosX. See vendor/die/LICENSE.
import fsgPatterns from '../../vendor/die/fsg-patterns.json' with { type: 'json' };
import entryRules from '../../vendor/die/entry-patterns.json' with { type: 'json' };
import manifest from '../../vendor/die/manifest.json' with { type: 'json' };
import { RESEARCH_RULES } from './research-signatures.js';
import { Bytes, matchHex } from './bytes.js';

export const DIE_SCOPE = Object.freeze({
  engine: 'die-rule-subset-js', fullEngine: false, commit: manifest.commit,
  families: ['FSG', 'UPX', 'MPRESS', ...entryRules.map(rule => rule.family)],
  coverage: ['FSG: 44 entry-point patterns', 'UPX: entry-point patterns; excludes patched-import heuristic', 'MPRESS: DOS-stub branch only',
    ...entryRules.map(rule => `${rule.family}: ${rule.patterns.length} direct entry byte-pattern branches only; no relative jumps, version overrides or fallback heuristics`),
    'local research (MT29): tElock loader transform constants, RL!de ASPack/FSG probes; bounded file scan with co-occurrence gates, x86 only'],
});

export function detect(bytes, pe) {
  const hits = [], ep = pe.entryPointOffset, reader = new Bytes(bytes);
  const compareEP = (pattern, delta = 0) => {
    const mapped = pe.rvaToOffset(pe.entryPointRva + delta, pattern.length / 2);
    return mapped !== null && matchHex(bytes, mapped, pattern);
  };
  const add = (family, version, evidence, source = 'die-rule-subset') => {
    if (!hits.some(h => h.family === family)) hits.push({ family, version, source, confidence: source === 'section-heuristic' ? 'low' : 'signature', evidence });
  };
  if (pe.machine === 0x14c && !pe.is64) {
    const fsg = fsgPatterns.find(rule => compareEP(rule.pattern));
    if (fsg) add('FSG', fsg.version, [{ kind: 'entry-point-pattern', offset: ep, pattern: fsg.pattern, options: fsg.options }]);
    for (const rule of entryRules) {
      if (rule.netExcluded && pe.isNet) continue;
      const match = rule.patterns.find(pattern => compareEP(pattern.pattern));
      if (match) add(rule.family, match.version, [{ kind: 'entry-point-pattern', offset: ep, pattern: match.pattern, options: match.options, ruleFile: rule.source, coverage: rule.coverage }]);
    }
    // Local research probes (research-signatures.js): bounded first-2-MiB scan,
    // co-occurrence gated so generic short sequences never fire alone. DIE
    // upstream branches above keep priority via the family dedup in add().
    if (!pe.isNet) {
      const scanLimit = Math.min(bytes.length, 0x200000);
      for (const rule of RESEARCH_RULES) {
        const hitProbes = [];
        for (const hex of rule.probes) {
          const pattern = new Uint8Array(hex.length / 2);
          for (let k = 0; k < pattern.length; k++) pattern[k] = parseInt(hex.slice(k * 2, k * 2 + 2), 16);
          let count = 0;
          if (pattern.length <= scanLimit) {
            const end = scanLimit - pattern.length;
            outer: for (let i = 0; i <= end; i++) {
              if (bytes[i] !== pattern[0]) continue;
              for (let j = 1; j < pattern.length; j++) if (bytes[i + j] !== pattern[j]) continue outer;
              if (++count >= 64) break;
            }
          }
          if (count > 0) hitProbes.push({ pattern: hex, count });
        }
        const satisfied = rule.required.every(hex => hitProbes.some(probe => probe.pattern === hex));
        if (satisfied && hitProbes.length >= rule.minHits) {
          add(rule.family, rule.version, [{ kind: 'research-probe-scan', probes: hitProbes, note: rule.note }], rule.source);
        }
      }
    }
  }
  if (!pe.isNet && [0x14c, 0x8664].includes(pe.machine)) {
    const offset = pe.is64 ? (compareEP('4889') ? 24 : 0) : (compareEP('807c') ? 27 : 0);
    const pattern = pe.is64 ? '53565755488D35........488DBE........57' : '60BE........8DBE........57';
    const modern = compareEP(pattern, offset);
    const old = !pe.is64 && compareEP('60e8000000005883e8..508db8........578db0........83cd..31db9090909001db75');
    if (modern || old) {
      const head = String.fromCharCode(...bytes.subarray(0, 1024));
      const marker = head.indexOf('$Id: UPX ');
      const version = marker >= 0 ? head.slice(marker + 9, marker + 13) : '';
      add('UPX', old ? '0.70' : (/^\d\.\d{2}$/.test(version) ? version : ''), [{ kind: 'entry-point-pattern', offset: ep + offset, pattern: old ? 'UPX 0.70' : pattern }]);
    }
  }
  if (bytes.length >= 0x200 && ["It's .NET EXE", 'Win32 .EXE.\r\n', 'Win64 .EXE.\r\n', 'Win32 .DLL.\r\n', 'Win64 .DLL.\r\n'].includes(reader.string(0x2e, 13))) {
    const marker = bytes.subarray(0x1f0, 0x200).indexOf(0x76);
    add('MPRESS', marker >= 0 ? reader.string(0x1f1 + marker, 15 - marker).trim() : '', [{ kind: 'dos-stub', offset: 0x2e }]);
  }
  const names = pe.sections.map(s => s.name.toLowerCase());
  const clues = [
    ['UPX', ['upx0', 'upx1']], ['MPRESS', ['.mpress1', '.mpress2']], ['ASPack', ['.aspack']],
    ['ASProtect', ['.aspr']], ['Petite', ['.petite']], ['NsPack', ['nsp0']],
    ['PECompact', ['pec1']], ['Enigma Virtual Box', ['.enigma1']], ['VMProtect', ['.vmp0']],
  ];
  for (const [family, sections] of clues) if (sections.every(s => names.includes(s))) {
    add(family, '', [{ kind: 'section-names', sections }], 'section-heuristic');
  }
  return hits;
}
