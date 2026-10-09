import { spawnSync } from 'node:child_process';

const suites = [
  'tests/dynamic.test.js',
  'tests/armadillo.test.js',
  'tests/armadillo-engine.test.js',
  'tests/instrument.test.js',
  'tests/concurrency.test.js',
];
const result = spawnSync(process.execPath, ['--test', ...suites], {
  env: { ...process.env, LIVE_SAMPLE_TESTS: '1', PYTHONIOENCODING: 'utf-8' },
  stdio: 'inherit',
});
process.exit(result.status ?? 1);
