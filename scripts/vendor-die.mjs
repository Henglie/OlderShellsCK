import { mkdir, writeFile, readFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';

const commit = '11cb5cb00f8763426005914ed3d983e729760749';
const root = new URL('../', import.meta.url);
const base = `https://raw.githubusercontent.com/horsicq/Detect-It-Easy/${commit}/`;
// Pinned candidates verified to exist at this commit: packer_Upack.2.sg and
// packer_PESpin.2.sg do not exist; the actual files are packer_WinUpack.2.sg
// (meta name "(Win)Upack") and protector_PESpin.2.sg. protector_PESpin.2.sg
// is not pinned: its only x86 branch resolves the version through a readByte
// switch (post-match override) and its two direct branches are AMD64-gated,
// outside the x86-only entry loop. packer_WWPack32.2.sg is not pinned: all
// three of its compareEP branches use the `eb$$` 1-byte relative-jump
// wildcard (help/Signatures.md), outside the byte/wildcard grammar here.
const additional = [
  { family: 'ASPack', file: 'db/PE/packer_ASPack.2.sg' },
  { family: 'Petite', file: 'db/PE/packer_Petite.2.sg' },
  { family: 'MEW', file: 'db/PE/packer_MEW.2.sg' },
  { family: 'PECompact', file: 'db/PE/packer_PECompact.2.sg' },
  // RLPack pins only the EXE form (nEP=0) of the DLL-prologue-shifted branches.
  { family: 'RLPack', file: 'db/PE/packer_RLPack.2.sg', coverage: 'direct-entry-byte-patterns-only; DLL prologue shift (nEP=11) variants excluded' },
  { family: 'tElock', file: 'db/PE/protector_tElock.2.sg' },
  // PELock's original script returns early on .NET/AMD64; the .NET gate is
  // carried as netExcluded (the entry loop is already x86-only), the
  // disassembler heuristic and import-position hash stay unported.
  { family: 'PELock', file: 'db/PE/protector_PELock.2.sg', netExcluded: true, coverage: 'direct-entry-byte-patterns-only; .NET excluded per the original script guard' },
  { family: 'NsPack', file: 'db/PE/packer_NsPack.2.sg' },
  { family: 'WinUpack', file: 'db/PE/packer_WinUpack.2.sg' },
];
const files = ['LICENSE', 'db/PE/packer_FSG.2.sg', 'db/PE/packer_UPX.2.sg', 'db/PE/packer_MPRESS.2.sg', ...additional.map(entry => entry.file)];
const sources = [];
const entryRules = [];
let fsgRules;
for (const file of files) {
  const destination = new URL(`vendor/die/${file}`, root);
  let bytes;
  try {
    // Cached pin first: the committed vendor tree is the reproducible source;
    // the network fetch is only a refresh path for missing files.
    bytes = Buffer.from(await readFile(destination));
  } catch {
    const response = await fetch(base + file);
    if (!response.ok) throw new Error(`${file}: HTTP ${response.status}`);
    bytes = Buffer.from(await response.arrayBuffer());
    await mkdir(new URL('.', destination), { recursive: true });
    await writeFile(destination, bytes);
  }
  sources.push({ path: file, sha256: createHash('sha256').update(bytes).digest('hex') });
  if (file.endsWith('packer_FSG.2.sg')) {
    fsgRules = [...bytes.toString('utf8').matchAll(/PE\.compareEP\("([a-fA-F0-9.]+)"\)\)\s*\{\s*sVersion = "([^"]+)";(?:\s*sOptions = "([^"]+)";)?/g)]
      .map(([, pattern, version, options]) => ({ pattern, version, options: options || '' }));
    if (fsgRules.length !== 44) throw new Error(`Unexpected FSG rule count: ${fsgRules.length}`);
  }
  const entry = additional.find(entry => file === entry.file);
  if (entry) {
    // Only direct entry-point byte/wildcard branches are extracted. Relative
    // jumps ($$ wildcard syntax), quoted byte strings, nested conditions and
    // heuristic fallbacks stay in the pinned original source, outside this
    // adapter's declared scope.
    const source = bytes.toString('utf8').replace(/\/\*[\s\S]*?\*\//g, '').replace(/\/\/[^\n]*/g, '');
    // A compareEP nested inside another pattern branch's body is a secondary
    // or override check, never a standalone entry rule, so every pattern
    // branch body becomes an exclusion zone before matching.
    const zones = [];
    for (const header of source.matchAll(/(?:if|else if)\s*\(\s*PE\.compare(?:EP)?\s*\(/g)) {
      const open = source.indexOf('{', header.index + header[0].length);
      if (open === -1) continue;
      let depth = 0;
      for (let i = open; i < source.length; i++) {
        if (source[i] === '{') depth++;
        else if (source[i] === '}' && --depth === 0) { zones.push([open, i]); break; }
      }
    }
    // ASPack keeps its PE.compare(..., nOffset) form (the patterns sit at the
    // entry-point offset via a helper). RLPack's ", nEP" is the DLL prologue
    // shift, pinned here only in its EXE (delta 0) meaning. A "||" disjunct
    // (PELock) keeps the byte pattern as the deciding evidence; "&&" guards
    // never match this form and are excluded with their branches.
    const expression = entry.family === 'ASPack'
      ? /(?:if|else if)\s*\(PE\.compare\("([a-fA-F0-9.]+)", nOffset\)\)\s*\{([^{}]*)\}/g
      : /(?:if|else if)\s*\(PE\.compareEP\("([a-fA-F0-9.]+)"(?:\s*,\s*nEP)?\)\s*(?:\|\|[^{}]*)?\)\s*\{([^{}]*)\}/g;
    const patterns = [...source.matchAll(expression)]
      .filter(match => !zones.some(([start, end]) => match.index > start && match.index < end))
      // Branches whose body opens nested conditions (e.g. RLPack's
      // follow-up compareEP at nEP+24) resolve the version from later bytes;
      // only trivial literal-assignment bodies are auditable standalone.
      .filter(match => /^(?:sVersion\s*=\s*"[^"]*";|sOptions\s*=\s*"[^"]*";|bDetected\s*=\s*true;|\s)+$/.test(match[2]))
      .map(match => ({
        pattern: match[1], version: /sVersion\s*=\s*"([^"]*)"/.exec(match[2])?.[1] || '', options: /sOptions\s*=\s*"([^"]*)"/.exec(match[2])?.[1] || '',
      }));
    if (!patterns.length) throw new Error(`No auditable direct patterns for ${entry.family}`);
    entryRules.push({ family: entry.family, source: file, coverage: entry.coverage || 'direct-entry-byte-patterns-only', ...(entry.netExcluded ? { netExcluded: true } : {}), patterns });
  }
}
await writeFile(new URL('vendor/die/manifest.json', root), JSON.stringify({ repository: 'horsicq/Detect-It-Easy', commit, license: 'MIT', files: sources }, null, 2) + '\n');
await writeFile(new URL('vendor/die/fsg-patterns.json', root), JSON.stringify(fsgRules, null, 2) + '\n');
await writeFile(new URL('vendor/die/entry-patterns.json', root), JSON.stringify(entryRules, null, 2) + '\n');
console.log(`Pinned ${sources.length} DIE source files at ${commit}`);
