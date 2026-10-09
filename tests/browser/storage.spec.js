import { test, expect } from '@playwright/test';

// T46 regression net for the historical firefox flake (PROGRESS icon-round note): the
// appearance controls must keep working when persistent storage is unavailable. The
// workbench variant drives the md-select overlay with coordinate clicks, which races the
// menu open animation in firefox; this spec drives selection with the keyboard and also
// pins the degradation contract: in-memory session preference, silent localStorage
// failure, clean fallback to system defaults after reload, zero page errors.

test('appearance and language degrade to session-only when localStorage access throws', async ({ page }) => {
  const errors = []; page.on('pageerror', error => errors.push(error.message));
  await page.addInitScript(() => Object.defineProperty(window, 'localStorage', { get() { throw new DOMException('blocked', 'SecurityError'); } }));
  await page.emulateMedia({ colorScheme: 'light' });
  await page.goto('/');
  await expect(page.getByRole('heading', { name: 'One entry point for legacy unpacking.' })).toBeVisible();
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'light');

  // Storage precheck: the restriction is really active in the page, so what follows
  // exercises the degraded path, not the happy one.
  await expect(page.evaluate(() => { localStorage; })).rejects.toThrow();

  // Keyboard navigation selects without racing the md-select menu animation.
  await page.getByRole('combobox', { name: 'Appearance' }).click();
  await page.getByRole('option', { name: 'Dark', exact: true }).waitFor();
  await page.keyboard.press('ArrowDown'); // system -> light
  await page.keyboard.press('ArrowDown'); // light -> dark
  await page.keyboard.press('Enter');
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'dark');

  await page.getByRole('combobox', { name: 'Language' }).click();
  await page.getByRole('option', { name: '中文', exact: true }).waitFor();
  await page.keyboard.press('ArrowUp'); // English -> 中文
  await page.keyboard.press('Enter');
  await expect(page.locator('html')).toHaveAttribute('lang', 'zh');
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'dark');
  await expect(page.getByRole('heading', { name: '让老壳分析，回到一个入口。' })).toBeVisible();

  // Reload drops the in-memory session and localStorage is unavailable: the app must
  // fall back to system defaults (emulated light scheme, en-US locale) instead of failing.
  await page.reload();
  await expect(page.getByRole('heading', { name: 'One entry point for legacy unpacking.' })).toBeVisible();
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'light');
  await expect(page.locator('html')).toHaveAttribute('lang', 'en');
  await expect(page.evaluate(() => { localStorage; })).rejects.toThrow();

  expect(errors).toEqual([]);
});
