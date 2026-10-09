import { SchemeTonalSpot, Hct, argbFromHex, hexFromArgb, MaterialDynamicColors } from '@material/material-color-utilities';
const session = new Map();
// Fixed brick-red Material theme seed; appearance toggling stays user-controlled.
const SEED = '#8f3d33';
export const getPreference = (key, fallback) => { if (session.has(key)) return session.get(key); try { return localStorage.getItem(`oldershells.${key}`) || fallback; } catch { return fallback; } };
export const setPreference = (key, value) => { session.set(key, value); try { localStorage.setItem(`oldershells.${key}`, value); } catch { /* Session-only in restricted storage. */ } };
const media = matchMedia('(prefers-color-scheme: dark)');
export function applyAppearance() {
  const mode = getPreference('theme', 'system');
  const dark = mode === 'dark' || (mode !== 'light' && media.matches);
  const scheme = new SchemeTonalSpot(Hct.fromInt(argbFromHex(SEED)), dark, 0);
  for (const role of ['primary', 'onPrimary', 'primaryContainer', 'onPrimaryContainer', 'secondary', 'onSecondary', 'secondaryContainer', 'onSecondaryContainer', 'tertiary', 'onTertiary', 'tertiaryContainer', 'onTertiaryContainer', 'surface', 'onSurface', 'onSurfaceVariant', 'surfaceVariant', 'surfaceContainerLowest', 'surfaceContainerLow', 'surfaceContainer', 'surfaceContainerHigh', 'surfaceContainerHighest', 'outline', 'outlineVariant', 'error', 'onError', 'errorContainer', 'onErrorContainer', 'inverseSurface', 'inverseOnSurface']) {
    const name = role.replace(/[A-Z]/g, c => `-${c.toLowerCase()}`);
    document.documentElement.style.setProperty(`--md-sys-color-${name}`, hexFromArgb(MaterialDynamicColors[role].getArgb(scheme)));
  }
  document.documentElement.dataset.theme = dark ? 'dark' : 'light';
  document.documentElement.style.colorScheme = dark ? 'dark' : 'light';
}
media.addEventListener('change', applyAppearance);
