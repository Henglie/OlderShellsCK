import test from 'node:test';
import assert from 'node:assert/strict';
import { messages } from '../src/web/i18n.js';
test('Chinese and English catalogs have identical nonempty keys', () => {
  assert.deepEqual(Object.keys(messages.zh).sort(), Object.keys(messages.en).sort());
  for (const translations of Object.values(messages)) for (const value of Object.values(translations)) assert.ok(typeof value === 'string' && value.length > 0);
});
