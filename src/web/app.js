import '@material/web/button/filled-button.js';
import '@material/web/button/filled-tonal-button.js';
import '@material/web/button/outlined-button.js';
import '@material/web/button/text-button.js';
import '@material/web/select/outlined-select.js';
import '@material/web/select/select-option.js';
import '@material/web/textfield/outlined-text-field.js';
import '@material/web/progress/linear-progress.js';
import '@material/web/dialog/dialog.js';
import { APP_VERSION } from '../core/version.js';
import { CATALOG } from '../core/catalog.js';
import { ENGINES } from '../core/engines.js';
import { DIE_SCOPE } from '../core/detect.js';
import { MAX_INPUT } from '../core/bytes.js';
import { translator } from './i18n.js';
import { icon } from './icons.js';
import { applyAppearance, getPreference, setPreference } from './theme.js';
import { WorkerPool } from './pool.js';

const root = document.querySelector('#app');
let locale = getPreference('language', navigator.language.startsWith('zh') ? 'zh' : 'en');
if (!['zh', 'en'].includes(locale)) locale = 'en';
let t = translator(locale), page = 'workbench', selected = null, serial = 0, toastTimer;
let queueNode, reportNode, oneClickNode;
const oneClickReady = item => !['failed', 'cancelled', 'unpacking'].includes(item.status);
const items = [], pool = new WorkerPool();
const node = (tag, className = '', text) => {
  const element = document.createElement(tag);
  if (className) element.className = className;
  if (text !== undefined) element.textContent = text;
  return element;
};
const button = (label, handler, type = 'text') => {
  const element = node(`md-${type}-button`, '', label); element.addEventListener('click', handler); return element;
};
const link = (label, href) => { const a = node('a', '', label); a.href = href; if (href.startsWith('https:')) { a.target = '_blank'; a.rel = 'noopener noreferrer'; } return a; };
const hex = value => value === null || value === undefined ? '—' : `0x${value.toString(16).toUpperCase()}`;
const warningsText = values => values.map(value => t(`warning.${value}`) === `warning.${value}` ? value : t(`warning.${value}`)).join(' · ');
const size = value => value < 1024 ? `${value} B` : value < 1048576 ? `${(value / 1024).toFixed(1)} KiB` : `${(value / 1048576).toFixed(1)} MiB`;
function toast(message) {
  document.querySelector('.toast')?.remove(); clearTimeout(toastTimer);
  const element = node('div', 'toast', message); element.setAttribute('role', 'status');
  root.append(element); toastTimer = setTimeout(() => element.remove(), 5000);
}
function download(bytes, name, type) {
  const url = URL.createObjectURL(new Blob([bytes], { type }));
  const a = link('', url); a.download = name; a.click(); setTimeout(() => URL.revokeObjectURL(url), 10000);
}
function selectControl(label, values, current, change) {
  const select = node('md-outlined-select'); select.label = label; select.setAttribute('aria-label', label);
  for (const [value, text] of values) {
    const option = node('md-select-option'); option.value = value; option.selected = value === current;
    const headline = node('div', '', text); headline.slot = 'headline'; option.append(headline); select.append(option);
  }
  select.value = current; select.addEventListener('change', () => change(select.value)); return select;
}
function hero(title, description) {
  const element = node('section', 'hero');
  element.append(node('span', 'eyebrow', `OlderShellsCK / ${t('preview')}`), node('h1', '', title), node('p', '', description)); return element;
}
function render() {
  document.documentElement.lang = locale; document.documentElement.dir = 'ltr'; document.title = `${t('app')} · OlderShellsCK`;
  const shell = node('div', 'shell'), header = node('header', 'topbar');
  const brand = node('div', 'brand');
  brand.append(icon('cube'), node('strong', '', t('app')), node('small', '', APP_VERSION));
  const nav = node('nav', 'topnav'); nav.setAttribute('aria-label', t('app'));
  for (const [id, glyph] of [['workbench', 'cube'], ['catalog', 'archive'], ['automation', 'terminal']]) {
    const action = button(t(id), () => { page = id; render(); }); action.prepend(icon(glyph, 'icon'));
    if (page === id) action.setAttribute('aria-current', 'page'); nav.append(action);
  }
  const controls = node('div', 'settings');
  controls.append(selectControl(t('language'), [['zh', '中文'], ['en', 'English']], locale, value => { locale = value; t = translator(locale); setPreference('language', value); render(); }));
  controls.append(selectControl(t('theme'), ['system', 'light', 'dark'].map(value => [value, t(value)]), getPreference('theme', 'system'), value => { setPreference('theme', value); applyAppearance(); }));
  controls.append(button(t('about'), showAbout));
  header.append(brand, nav, controls);
  const main = node('main', 'main');
  if (page === 'workbench') renderWorkbench(main);
  if (page === 'catalog') renderCatalog(main);
  if (page === 'automation') renderAutomation(main);
  main.append(node('p', 'footer-note', t('experimentalOnly')));
  const footer = node('footer', 'page-footer');
  footer.append(node('span', '', `${t('subtitle')} · ${t('local')}`), link(t('docs'), './README.md'), link('Apache-2.0', './LICENSE'));
  shell.append(header, main, footer); root.replaceChildren(shell);
}
function renderWorkbench(main) {
  main.append(hero(t('hero'), t('intro')));
  const stats = node('div', 'stats');
   for (const [value, label] of [[String(ENGINES.length), 'engineCount'], [String(CATALOG.length), 'researchCount'], [String(DIE_SCOPE.families.length), 'detectionScope']]) {
    const stat = node('div', 'stat'); stat.append(node('strong', '', value), node('span', '', t(label))); stats.append(stat);
  }
  const drop = node('section', 'dropzone'); drop.setAttribute('aria-label', t('drop'));
  const copy = node('div'); copy.append(node('h2', '', t('drop')), node('p', 'muted', t('dropHint')));
  const input = node('input'); input.type = 'file'; input.multiple = true; input.hidden = true; input.id = 'file-input';
  input.addEventListener('change', () => { addFiles([...input.files]); input.value = ''; });
  const dropActions = node('div', 'drop-actions');
  oneClickNode = button(t('oneClick'), oneClickUnpack, 'filled-tonal'); oneClickNode.disabled = true;
  dropActions.append(button(t('select'), () => input.click(), 'filled'), oneClickNode, input);
  drop.append(icon('upload'), copy, dropActions);
  drop.addEventListener('dragover', event => { event.preventDefault(); drop.classList.add('drag'); });
  drop.addEventListener('dragleave', () => drop.classList.remove('drag'));
  drop.addEventListener('drop', event => { event.preventDefault(); drop.classList.remove('drag'); addFiles([...event.dataTransfer.files]); });
  const workspace = node('div', 'workspace'), queuePanel = node('section', 'panel queue-panel');
  const heading = node('div', 'panel-head'); heading.append(node('h2', '', t('queue')), button(t('clear'), clear));
  queueNode = node('div', 'queue-list'); queueNode.setAttribute('aria-label', t('queue'));
  reportNode = node('section', 'panel report-panel'); reportNode.setAttribute('aria-label', t('report'));
  queuePanel.append(heading, queueNode, button(t('cancel'), () => { pool.cancel(); toast(t('cancelHint')); }));
  workspace.append(queuePanel, reportNode);
  main.append(stats, drop, node('p', 'privacy', t('localHint')), workspace);
  updateWorkspace();
}
function updateWorkspace() {
  if (page !== 'workbench' || !queueNode || !reportNode) return;
  if (oneClickNode) oneClickNode.disabled = !items.some(oneClickReady);
  const nodes = items.map(item => {
    const entry = node('button', `file-item${item.id === selected ? ' active' : ''}`);
    entry.type = 'button'; entry.setAttribute('aria-pressed', String(item.id === selected));
    entry.append(node('strong', '', item.file.name), node('small', '', `${size(item.file.size)} · ${t(item.status)}`));
    entry.addEventListener('click', () => { selected = item.id; updateWorkspace(); }); return entry;
  });
  queueNode.replaceChildren(...nodes);
  renderReport(items.find(item => item.id === selected));
}
function oneClickUnpack() {
  const ready = items.filter(oneClickReady);
  if (!ready.length) return;
  for (const item of ready) void processFile(item, 'unpack');
  toast(t('oneClickHint'));
}
function clear() { pool.cancel(); items.splice(0); selected = null; updateWorkspace(); }
function addFiles(files) {
  if (!globalThis.Worker || !globalThis.crypto?.subtle) { toast(t('browser')); return; }
  if (items.length + files.length > 16) { toast(t('tooMany')); return; }
  for (const file of files) {
    const item = { id: ++serial, file, status: 'queued' }; items.push(item); if (selected === null) selected = item.id;
    if (!file.size || file.size > MAX_INPUT) { item.status = 'failed'; item.error = { code: 'input-size-limit' }; continue; }
    void processFile(item, 'analyze');
  }
  updateWorkspace();
}
async function processFile(item, operation) {
  if (item.status === 'unpacking') return;
  item.error = null;
  if (operation === 'unpack') { item.output = null; item.status = 'unpacking'; }
  try {
    const result = await pool.run(item.file, operation, { name: item.file.name, engine: item.engine || 'auto' }, () => { item.status = operation === 'unpack' ? 'unpacking' : 'analyzing'; updateWorkspace(); });
    if (operation === 'analyze') item.report = result; else item.output = result;
    item.status = 'done';
  } catch (error) { item.error = error; item.status = error.code === 'cancelled' ? 'cancelled' : 'failed'; }
  updateWorkspace();
}
function renderReport(item) {
  reportNode.replaceChildren();
  if (!item) {
    const empty = node('div', 'empty'); empty.append(icon('cube'), node('strong', '', t('empty')), node('p', '', t('emptyHint'))); reportNode.append(empty); return;
  }
  reportNode.append(node('h2', 'file-title', item.file.name));
  if (['queued', 'analyzing', 'unpacking'].includes(item.status)) {
    const progress = node('md-linear-progress'); progress.indeterminate = true; progress.setAttribute('aria-label', t(item.status));
    reportNode.append(progress, node('p', 'muted', t(item.status)));
  }
  if (item.error) {
    const error = node('div', 'notice error'); error.setAttribute('role', 'alert');
    error.append(node('strong', '', t(item.status === 'cancelled' ? 'cancelled' : 'error')), node('p', '', t(item.error.code === 'input-size-limit' ? 'limit' : 'errorHint')), node('code', '', item.error.code)); reportNode.append(error);
  }
  if (!item.report) return;
  const report = item.report, facts = node('dl', 'facts');
  for (const [label, value] of [['format', report.pe.format], ['architecture', report.pe.architecture], ['size', size(report.file.size)], ['entry', hex(report.pe.entryPointRva)]]) {
    const fact = node('div'); fact.append(node('dt', '', t(label)), node('dd', '', value)); facts.append(fact);
  }
  reportNode.append(facts, node('p', 'hash mono', `SHA-256  ${report.file.sha256}`), node('h3', '', t('findings')));
  if (!report.detections.length) reportNode.append(node('p', 'muted', t('noFinding')));
  for (const hit of report.detections) {
    const finding = node('div', 'finding'), tags = node('div', 'chips');
    tags.append(node('strong', '', hit.family), node('span', 'chip accent', t(hit.confidence)), node('span', 'chip', hit.version || t('unknownVersion')));
    finding.append(tags, node('p', 'muted', t(hit.source === 'section-heuristic' ? 'sourceHeuristic' : 'sourceSubset')));
    const detail = node('details'); detail.append(node('summary', '', t('details')), node('pre', '', JSON.stringify(hit.evidence, null, 2))); finding.append(detail); reportNode.append(finding);
  }
  reportNode.append(node('p', 'notice', t('dieNotice')), node('h3', '', t('sections')));
  const rows = report.pe.sections.map(section => [section.name, hex(section.rva), hex(section.rawOffset), size(section.rawSize), size(section.virtualSize), String(section.entropy)]);
  reportNode.append(table(['section', 'entry', 'offset', 'rawSize', 'virtualSize', 'entropy'], rows));
  const imports = node('details'); imports.append(node('summary', '', `${t('imports')} · ${report.pe.importsEnumerated === false ? t('notEnumerated') : report.pe.imports.length}`), node('pre', '', JSON.stringify(report.pe.imports, null, 2))); reportNode.append(imports);
  if (report.pe.warnings.length) reportNode.append(node('p', 'notice', `${t('warnings')}: ${warningsText(report.pe.warnings)}`));
  const actions = node('div', 'actions');
  if (report.candidates.length) {
    const chooser = selectControl(t('engine'), [['auto', t('autoEngine')], ...report.candidates.map(candidate => [candidate.id, candidate.family])], item.engine || 'auto', value => { item.engine = value; });
    chooser.disabled = item.status === 'unpacking';
    reportNode.append(chooser);
    for (const candidate of report.candidates) reportNode.append(node('p', 'notice', `${candidate.family} · ${candidate.variant} · ${t(candidate.outputKind)}`));
    const unpack = button(t('unpack'), () => void processFile(item, 'unpack'), 'filled'); unpack.disabled = item.status === 'unpacking'; actions.append(unpack);
  }
  actions.append(button(t('export'), () => download(JSON.stringify({ input: report, output: item.output ? { metadata: item.output.metadata, report: item.output.report } : null }, null, 2), `${item.file.name}.report.json`, 'application/json'), 'outlined'));
  reportNode.append(actions, node('p', 'notice', t(report.candidates.length ? 'unpackNotice' : 'unsupported')));
  if (item.output) {
    const kind = item.output.metadata.outputKind;
    const success = node('div', `notice ${kind === 'analysis-pe' ? 'analysis-only' : 'success'}`);
    success.setAttribute('data-output-kind', kind);
    const heading = kind === 'analysis-pe' ? 'analysisReady' : kind === 'dump-pe' ? 'dumpReady' : kind === 'extract-pe' ? 'extractReady' : 'rebuilt';
    const notice = kind === 'analysis-pe' ? 'analysisNotice' : kind === 'dump-pe' ? 'dumpNotice' : kind === 'extract-pe' ? 'extractNotice' : 'runtimeNotice';
    success.append(node('strong', '', t(heading)), node('p', '', t(notice)), node('code', '', `OEP ${hex(item.output.metadata.originalEntryPoint)} · ${size(item.output.bytes.length)}`));
    if (item.output.metadata.warnings.length) success.append(node('p', '', `${t('warnings')}: ${warningsText(item.output.metadata.warnings)}`));
    if (item.output.metadata.unrestoredMetadata?.length) success.append(node('p', '', `${t('unrestored')}: ${item.output.metadata.unrestoredMetadata.join(', ')}`));
    const label = kind === 'analysis-pe' ? 'downloadAnalysis' : 'download';
    reportNode.append(success, button(t(label), () => download(item.output.bytes, item.output.name, 'application/octet-stream'), 'filled-tonal'));
  }
  const details = node('details'); details.append(node('summary', '', t('details')), node('pre', '', JSON.stringify(report, null, 2))); reportNode.append(details);
}
function table(headers, rows) {
  const wrap = node('div', 'table-wrap'), element = node('table'), head = node('thead'), tr = node('tr');
  for (const title of headers) { const th = node('th', '', t(title)); th.scope = 'col'; tr.append(th); }
  head.append(tr); element.append(head); const body = node('tbody');
  for (const cells of rows) { const row = node('tr'); for (const content of cells) { const cell = node('td'); content instanceof Node ? cell.append(content) : cell.textContent = content; row.append(cell); } body.append(row); }
  element.append(body); wrap.append(element); return wrap;
}
const SERVER_ENGINES = {
  upx: [['upx-official', 'rebuilt-pe', 'external'], ['emulated-pe32', 'dump-pe', 'emulated']],
  dynamic: [['dynamic-debug-dump', 'dump-pe', 'dynamic'], ['instrumented-exception-dump', 'extract-pe', 'instrument']],
  aspack: [['aspack-pe32-huffman', 'analysis-pe', 'static']],
  mew: [['mew-pe32-lzma1', 'rebuilt-pe', 'static']],
  armadillo: [['armadillo-nanomites', 'dump-pe', 'native']],
};
function renderCatalog(main) {
  main.append(hero(t('catalogTitle'), t('catalogHint')), node('p', 'notice', t('serverEngineNote')));
  const search = node('md-outlined-text-field', 'search'); search.label = t('search'); search.setAttribute('aria-label', t('search'));
  const results = node('div');
  const update = () => {
    const term = search.value.toLowerCase();
    const entries = CATALOG.filter(entry => `${entry.family} ${entry.reference}`.toLowerCase().includes(term));
    results.replaceChildren(entries.length ? table(['family', 'category', 'route', 'status', 'engines', 'outputKind', 'source'], entries.map(entry => {
      const server = SERVER_ENGINES[entry.id] || [];
      const experimental = entry.stage === 'experimental' || server.length > 0;
      const engines = node('div');
      for (const [id, route, isServer] of [...entry.engineIds.map(engineId => [engineId, 'static', false]), ...server.map(([id, , route]) => [id, route, true])]) {
        const line = node('div');
        line.append(node('code', '', id), node('span', 'muted', ` · ${t(route)}`));
        if (isServer) line.append(node('span', 'muted', ` · ${t('serverOnly')}`));
        engines.append(line);
      }
      const kinds = [...new Set([...entry.outputKinds, ...server.map(([, kind]) => kind)])];
      return [entry.family, t(entry.category), t(entry.route), node('span', `chip${experimental ? ' accent' : ''}`, t(experimental ? 'experimental' : 'researched')), entry.engineIds.length || server.length ? engines : '—', kinds.length ? kinds.map(kind => t(kind)).join(' / ') : '—', link(entry.reference, entry.source)];
    })) : node('p', 'muted', t('emptySearch')));
  };
  search.addEventListener('input', update); main.append(search, results, link(t('researchLink'), './docs/research/die-and-packers.md')); update();
}
function renderAutomation(main) {
  main.append(hero(t('apiTitle'), t('apiHint')));
  const grid = node('div', 'api-grid'), http = node('section', 'panel'), mcp = node('section', 'panel');
  http.append(icon('terminal'), node('h3', '', t('http')), node('p', '', t('httpText')),
    node('pre', '', 'npm start\n\nGET  http://127.0.0.1:8787/api/v1/capabilities\nPOST http://127.0.0.1:8787/api/v1/analyze\nPOST http://127.0.0.1:8787/api/v1/unpack\n\n{\n  "name": "sample.exe",\n  "dataBase64": "..."\n}'), link(t('apiDocs'), './docs/API.md'));
  mcp.append(icon('cube'), node('h3', '', t('mcp')), node('p', '', t('mcpText')),
    node('pre', '', JSON.stringify({ mcpServers: { oldershellsck: { command: 'node', args: ['/path/to/OlderShellsCK/src/server/mcp.js'] } } }, null, 2)),
    node('h3', '', t('tools')), node('code', '', 'list_capabilities · analyze_file · unpack_file'));
  grid.append(http, mcp); main.append(grid);
}
function showAbout() {
  const dialog = node('md-dialog'), heading = node('div', '', `${t('app')} ${APP_VERSION}`); heading.slot = 'headline';
  const content = node('div'); content.slot = 'content'; content.append(node('p', '', t('aboutText')), link(t('notices'), './NOTICE'));
  const close = button(t('close'), () => dialog.close()); close.slot = 'actions'; dialog.append(heading, content, close); root.append(dialog);
  dialog.addEventListener('closed', () => dialog.remove()); dialog.show();
}
applyAppearance(); render();
