import { allEngines } from './engines.js';

const rows = [
  ['dynamic', 'Generic dynamic dump', 'bundle', 'dynamic', 'dump_oep debugger', ''],
  ['upx', 'UPX', 'packer', 'external', 'UPX official / RetDec', 'https://github.com/upx/upx'],
  ['aspack', 'ASPack', 'packer', 'static', 'XStaticUnpacker', 'https://github.com/horsicq/XStaticUnpacker'],
  ['fsg', 'FSG', 'packer', 'static', 'XStaticUnpacker', 'https://github.com/horsicq/XStaticUnpacker'],
  ['mew', 'MEW', 'packer', 'static', 'XStaticUnpacker', 'https://github.com/horsicq/XStaticUnpacker'],
  ['petite', 'Petite', 'packer', 'emulated', 'XStaticUnpacker', 'https://github.com/horsicq/XStaticUnpacker'],
  ['mpress', 'MPRESS', 'packer', 'static', 'RetDec', 'https://github.com/avast/retdec'],
  ['yzpack', 'YZPack', 'packer', 'emulated', 'unipacker', 'https://github.com/unipacker/unipacker'],
  ['nspack', 'NsPack', 'packer', 'static', 'XStaticUnpacker', 'https://github.com/horsicq/XStaticUnpacker'],
  ['upack', 'Upack / WinUpack', 'packer', 'static', 'ClamAV', 'https://github.com/Cisco-Talos/clamav'],
  ['wwpack', 'WWPack32', 'packer', 'static', 'ClamAV', 'https://github.com/Cisco-Talos/clamav'],
  ['pespin', 'PESpin', 'protector', 'static', 'ClamAV', 'https://github.com/Cisco-Talos/clamav'],
  ['yoda', "y0da’s Crypter", 'protector', 'emulated', 'XStaticUnpacker', 'https://github.com/horsicq/XStaticUnpacker'],
  ['pecompact', 'PECompact', 'packer', 'research', '52pojie', 'https://down.52pojie.cn/Tools/Unpackers/'],
  ['asprotect', 'ASProtect', 'protector', 'research', '52pojie', 'https://down.52pojie.cn/Tools/Unpackers/'],
  ['armadillo', 'Armadillo / SoftwarePassport', 'protector', 'native', 'Armageddon', 'https://down.52pojie.cn/Tools/Unpackers/'],
  ['rlpack', 'RLPack', 'packer', 'research', 'DIE', 'https://github.com/horsicq/Detect-It-Easy'],
  ['telock', 'tElock', 'protector', 'research', 'DIE', 'https://github.com/horsicq/Detect-It-Easy'],
  ['pelock', 'PELock', 'protector', 'research', 'DIE', 'https://github.com/horsicq/Detect-It-Easy'],
  ['acprotect', 'ACProtect', 'protector', 'research', 'DIE', 'https://github.com/horsicq/Detect-It-Easy'],
  ['execryptor', 'EXECryptor', 'protector', 'research', 'DIE', 'https://github.com/horsicq/Detect-It-Easy'],
  ['obsidium', 'Obsidium', 'protector', 'research', 'DIE', 'https://github.com/horsicq/Detect-It-Easy'],
  ['themida', 'Themida / WinLicense', 'virtualizer', 'native', 'unlicense', 'https://github.com/ergrelet/unlicense'],
  ['vmprotect', 'VMProtect', 'virtualizer', 'research', 'DIE', 'https://github.com/horsicq/Detect-It-Easy'],
  ['enigma', 'Enigma Protector', 'virtualizer', 'research', 'DIE', 'https://github.com/horsicq/Detect-It-Easy'],
  ['codevirtualizer', 'Code Virtualizer', 'virtualizer', 'research', 'Oreans', 'https://www.oreans.com/codevirtualizer.php'],
  ['zprotect', 'ZProtect', 'protector', 'research', '52pojie', 'https://down.52pojie.cn/Tools/Packers/'],
  ['steamstub', 'SteamStub', 'protector', 'static', 'Steamless (restricted license)', 'https://github.com/atom0s/Steamless'],
  ['evb', 'Enigma Virtual Box', 'bundle', 'static', 'XStaticUnpacker', 'https://github.com/horsicq/XStaticUnpacker'],
  ['molebox', 'MoleBox', 'bundle', 'static', 'demoleition', 'https://lifeinhex.com/tag/molebox/'],
  ['boxedapp', 'BoxedApp Packer', 'bundle', 'static', 'XStaticUnpacker', 'https://github.com/horsicq/XStaticUnpacker'],
  ['autoit', 'AutoIt', 'bundle', 'static', 'XStaticUnpacker', 'https://github.com/horsicq/XStaticUnpacker'],
  ['pyinstaller', 'PyInstaller', 'bundle', 'static', 'pyinstxtractor-go', 'https://github.com/pyinstxtractor/pyinstxtractor-go'],
  ['inno', 'Inno Setup', 'bundle', 'static', 'innoextract', 'https://github.com/dscharrer/innoextract'],
  ['installshield', 'InstallShield CAB', 'bundle', 'static', 'unshield', 'https://github.com/twogood/unshield'],
];

const build = () => rows.map(([id, family, category, route, reference, source]) => {
  const engines = allEngines().filter(engine => engine.metadata.catalogId === id).map(engine => engine.metadata);
  return Object.freeze({ id, family, category, route, reference, source,
    stage: engines.length ? 'experimental' : 'researched', variant: engines.map(engine => engine.variant).join('; ') || null,
    engineIds: engines.map(engine => engine.id), outputKinds: [...new Set(engines.map(engine => engine.outputKind))],
    runtimeVerified: engines.length > 0 && engines.every(engine => engine.runtimeVerified) });
});
export let CATALOG = Object.freeze(build());
export function rebuildCatalog() { CATALOG = Object.freeze(build()); }
