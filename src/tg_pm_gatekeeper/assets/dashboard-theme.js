// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 GeniusLv2006 and contributors
// Loaded synchronously in <head> so the resolved theme is set before first paint.
(() => {
  const storageKey = 'gatekeeper-theme';
  const choices = ['system', 'light', 'dark'];
  const labels = {system: 'System', light: 'Light', dark: 'Dark'};
  const media = window.matchMedia('(prefers-color-scheme: dark)');
  const root = document.documentElement;

  const readChoice = () => {
    try {
      const stored = window.localStorage.getItem(storageKey);
      return choices.includes(stored) ? stored : 'system';
    } catch (_error) {
      return 'system';
    }
  };

  const apply = (choice) => {
    const dark = choice === 'dark' || (choice === 'system' && media.matches);
    root.dataset.theme = dark ? 'dark' : 'light';
    root.dataset.themeChoice = choice;
    const button = document.querySelector('[data-theme-toggle]');
    if (button) {
      button.textContent = labels[choice];
      button.setAttribute('aria-label', `Theme: ${labels[choice]}. Change theme`);
      button.title = `Theme: ${labels[choice]}`;
    }
  };

  let current = readChoice();
  apply(current);
  media.addEventListener('change', () => apply(current));

  document.addEventListener('DOMContentLoaded', () => {
    apply(current);
    document.querySelector('[data-theme-toggle]')?.addEventListener('click', () => {
      const next = choices[(choices.indexOf(current) + 1) % choices.length];
      try {
        if (next === 'system') window.localStorage.removeItem(storageKey);
        else window.localStorage.setItem(storageKey, next);
      } catch (_error) {
        // Without storage the choice still applies to this page view.
      }
      current = next;
      apply(current);
    });
  });
})();
