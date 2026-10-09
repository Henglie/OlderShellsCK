import { test, expect } from '@playwright/test';
import { readFile, access } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
const fixture = fileURLToPath(new URL('../../test-results/fixtures/mpress.exe', import.meta.url));

test('official M3 components, persisted locale/theme, catalog and mobile layout', async ({ page }) => {
  const errors = []; page.on('pageerror', error => errors.push(error.message));
  await page.goto('/');
  await expect(page.getByRole('heading', { name: 'One entry point for legacy unpacking.' })).toBeVisible();
  expect(await page.locator('md-filled-button').first().evaluate(element => Boolean(element.shadowRoot?.querySelector('button')))).toBe(true);
  for (const navButton of await page.locator('.topnav md-text-button').all()) {
    const icon = await navButton.evaluate(element => {
      const slotted = element.querySelector('svg[slot="icon"]');
      return slotted && getComputedStyle(slotted).display;
    });
    expect(icon).toBeTruthy(); // a missing slot leaves the icon outside the button's flex row
  }
  await page.emulateMedia({ colorScheme: 'dark' });
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'dark');
  await page.getByRole('combobox', { name: 'Appearance' }).click();
  await page.getByRole('option', { name: 'Light', exact: true }).click();
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'light');
  const primary = await page.evaluate(() => getComputedStyle(document.documentElement).getPropertyValue('--md-sys-color-primary').trim());
  expect(primary.toLowerCase()).toBe('#904a41'); // official HCT tonal spot of the fixed brick-red seed #8f3d33
  await page.getByRole('combobox', { name: 'Language' }).click();
  await page.getByRole('option', { name: '中文', exact: true }).click();
  await expect(page.locator('html')).toHaveAttribute('lang', 'zh');
  await page.reload();
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'light');
  await expect(page.getByRole('heading', { name: '让老壳分析，回到一个入口。' })).toBeVisible();
  await page.getByRole('button', { name: '能力目录', exact: true }).click();
  await page.getByRole('textbox', { name: '搜索壳族或工具' }).fill('MPRESS');
  await expect(page.locator('tbody tr')).toHaveCount(1);
  await expect(page.locator('tbody')).toContainText('实验性');
  await page.getByRole('button', { name: 'API 与 MCP', exact: true }).click();
  await expect(page.locator('main')).toContainText('list_capabilities');
  await page.setViewportSize({ width: 390, height: 844 });
  await page.getByRole('button', { name: '分析工作台', exact: true }).click();
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
  await page.screenshot({ path: test.info().outputPath('mobile.png'), fullPage: true });
  expect(errors).toEqual([]);
});

test('browser worker analyzes and unpacks the pinned MPRESS fixture without uploads', async ({ page }) => {
  try { await access(fixture); } catch { test.skip(true, 'Run node scripts/fetch-fixtures.mjs'); }
  const errors = [], uploads = [], remote = [];
  page.on('pageerror', error => errors.push(error.message));
  page.on('request', request => { if (request.method() === 'POST') uploads.push(request.url()); if (!request.url().startsWith('http://127.0.0.1:8791')) remote.push(request.url()); });
  await page.goto('/');
  await page.locator('#file-input').setInputFiles(fixture);
  await expect(page.locator('.report-panel')).toContainText('2.19');
  await expect(page.locator('.report-panel')).toContainText('218d5569194ee018b354c9f717047ae2dac5d6130cdf81eb24f0a9b370600136');
  await page.getByRole('button', { name: 'Try static unpacking', exact: true }).click();
  await expect(page.locator('.report-panel')).toContainText('PE structure rebuilt');
  const downloaded = page.waitForEvent('download');
  await page.getByRole('button', { name: 'Download rebuilt PE', exact: true }).click();
  const artifact = await downloaded;
  const bytes = await readFile(await artifact.path());
  expect(bytes.subarray(0, 2).toString()).toBe('MZ'); expect(bytes.length).toBeGreaterThan(8192);
  const reportDownload = page.waitForEvent('download');
  await page.getByRole('button', { name: 'Export JSON', exact: true }).click();
  const json = JSON.parse(await readFile(await (await reportDownload).path(), 'utf8'));
  expect(json.output.metadata.originalEntryPoint).toBe(0x1110);
  expect(json.output.metadata.runtimeVerified).toBe(true);
  await page.evaluate(() => window.scrollTo(0, 0));
  await page.screenshot({ path: test.info().outputPath('workbench.png'), fullPage: true });
  expect(errors).toEqual([]); expect(uploads).toEqual([]); expect(remote).toEqual([]);
});

test('invalid files stay data and report stable errors; queue clears', async ({ page }) => {
  await page.goto('/');
  await page.locator('#file-input').setInputFiles({ name: '<img onerror=alert(1)>.exe', mimeType: 'application/octet-stream', buffer: Buffer.from('this is not a PE executable') });
  await expect(page.getByRole('alert')).toContainText('not-pe');
  await expect(page.locator('.report-panel img')).toHaveCount(0);
  await page.getByRole('button', { name: 'Clear', exact: true }).click();
  await expect(page.locator('.file-item')).toHaveCount(0);
  await expect(page.locator('.report-panel')).toContainText('Choose a file to explore its structure.');
});

test('appearance controls still work when persistent storage is unavailable', async ({ page }) => {
  await page.addInitScript(() => Object.defineProperty(window, 'localStorage', { get() { throw new DOMException('blocked', 'SecurityError'); } }));
  await page.emulateMedia({ colorScheme: 'light' });
  await page.goto('/');
  await page.getByRole('combobox', { name: 'Appearance' }).click();
  await page.getByRole('option', { name: 'Dark', exact: true }).click();
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'dark');
  await page.getByRole('combobox', { name: 'Language' }).click();
  await page.getByRole('option', { name: '中文', exact: true }).click();
  await expect(page.locator('html')).toHaveAttribute('lang', 'zh');
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'dark');
});

test('one-click unpack auto-selects engines; refusals stay explicit', async ({ page }) => {
  const files = ['mpress.exe', 'fsg/fsg133.bin', 'aspack/aspack-lbop20.bin'].map(name => fileURLToPath(new URL(`../../test-results/fixtures/${name}`, import.meta.url)));
  for (const file of files) { try { await access(file); } catch { test.skip(true, 'Run the fetch-*-fixtures.mjs scripts first'); } }
  const errors = []; page.on('pageerror', error => errors.push(error.message));
  await page.goto('/');
  const oneClick = page.getByRole('button', { name: 'One-click unpack', exact: true });
  await expect(oneClick).toBeDisabled();
  await page.locator('#file-input').setInputFiles(files);
  await expect(oneClick).toBeEnabled();
  await oneClick.click();
  await expect(page.locator('.file-item', { hasText: 'mpress.exe' }).first()).toBeVisible();
  await page.locator('.file-item', { hasText: 'mpress.exe' }).click();
  await expect(page.locator('.report-panel')).toContainText('PE structure rebuilt', { timeout: 60000 });
  await page.locator('.file-item', { hasText: 'fsg133.bin' }).click();
  await expect(page.locator('.report-panel')).toContainText('PE structure rebuilt', { timeout: 60000 });
  await page.locator('.file-item', { hasText: 'aspack-lbop20.bin' }).click();
  await expect(page.locator('.report-panel code', { hasText: 'unsupported-variant' })).toBeVisible({ timeout: 60000 });
  expect(errors).toEqual([]);
});

for (const [name, relative, family, kind] of [['FSG', 'fsg/fsg133.bin', 'FSG', 'rebuilt'], ['UPX', 'upx/lbop20.upx.bin', 'UPX', 'rebuilt'], ['UPX analysis-only', 'upx/lzma-424.upx.bin', 'UPX', 'analysis']]) {
  test(`${name} download is labeled with its verified grade`, async ({ page }) => {
    const file = fileURLToPath(new URL(`../../test-results/fixtures/${relative}`, import.meta.url));
    try { await access(file); } catch { test.skip(true, `Fetch ${family} fixtures first`); }
    await page.goto('/');
    await page.locator('#file-input').setInputFiles(file);
    await expect(page.locator('.report-panel')).toContainText(family);
    await page.getByRole('combobox', { name: 'Unpacking engine' }).click();
    await page.getByRole('option', { name: family, exact: true }).click();
    await page.getByRole('button', { name: 'Try static unpacking', exact: true }).click();
    if (kind === 'rebuilt') {
      await expect(page.locator('[data-output-kind="rebuilt-pe"]')).toContainText('PE structure rebuilt');
      await expect(page.getByRole('button', { name: 'Download analysis PE', exact: true })).toHaveCount(0);
    } else {
      await expect(page.locator('[data-output-kind="analysis-pe"]')).toContainText('Analysis-only PE generated');
      await expect(page.getByRole('button', { name: 'Download rebuilt PE', exact: true })).toHaveCount(0);
    }
    const download = page.waitForEvent('download');
    await page.getByRole('button', { name: kind === 'rebuilt' ? 'Download rebuilt PE' : 'Download analysis PE', exact: true }).click();
    const artifact = await download;
    expect(artifact.suggestedFilename()).toMatch(kind === 'rebuilt' ? /\.unpacked\.exe$/ : /\.analysis\.exe$/);
    expect((await readFile(await artifact.path())).subarray(0, 2).toString()).toBe('MZ');
  });
}

test('catalog grades ASPack and MEW experimental and states the browser engine limits', async ({ page }) => {
  const errors = []; page.on('pageerror', error => errors.push(error.message));
  await page.goto('/');
  await page.getByRole('button', { name: 'Capabilities', exact: true }).click();
  await expect(page.locator('main')).toContainText('7 of the 10 engines run server-side only');
  for (const [family, engineId] of [['ASPack', 'aspack-pe32-huffman'], ['MEW', 'mew-pe32-lzma1']]) {
    await page.getByRole('textbox', { name: 'Search families or tools' }).fill(family);
    await expect(page.locator('tbody tr')).toHaveCount(1);
    await expect(page.locator('tbody .chip.accent')).toHaveText('Experimental');
    await expect(page.locator('tbody')).toContainText(engineId);
    await expect(page.locator('tbody')).toContainText('Server-side engine');
  }
  await page.getByRole('combobox', { name: 'Language' }).click();
  await page.getByRole('option', { name: '中文', exact: true }).click();
  await expect(page.locator('main')).toContainText('10 个引擎中 7 个仅在服务器端运行');
  await page.getByRole('textbox', { name: '搜索壳族或工具' }).fill('MEW');
  await expect(page.locator('tbody .chip.accent')).toHaveText('实验性');
  expect(errors).toEqual([]);
});
