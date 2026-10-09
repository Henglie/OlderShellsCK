import { defineConfig } from '@playwright/test';
export default defineConfig({
  testDir: './tests/browser',
  outputDir: './test-results/browser',
  fullyParallel: true,
  workers: 3,
  timeout: 45000,
  use: { baseURL: 'http://127.0.0.1:8791', locale: 'en-US', screenshot: 'only-on-failure', trace: 'retain-on-failure' },
  projects: [
    { name: 'chromium', use: { browserName: 'chromium' } },
    { name: 'firefox', use: { browserName: 'firefox', launchOptions: { slowMo: 250 } } }, // firefox-only: lets the md-select menu become interactive between clicks; coordinate-click race observed only in firefox (T46)
    { name: 'webkit', use: { browserName: 'webkit' } },
  ],
  webServer: { command: 'node src/server/http.js', env: { PORT: '8791' }, url: 'http://127.0.0.1:8791', reuseExistingServer: false },
});
