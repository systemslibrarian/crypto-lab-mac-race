import '../styles/main.css';

import { runCmacSelfTest } from './cmac';
import { runGhashSelfTest } from './ghash';
import { runHmacSelfTest } from './hmac';
import { runLengthExtensionSelfTest } from './lengthext';
import { runPoly1305SelfTest } from './poly1305';
import { runTimingSelfTest } from './timing';
import { renderApp } from './ui';

function wireThemeToggle(): void {
  const root = document.documentElement;
  const button = document.querySelector<HTMLButtonElement>('#theme-toggle');
  if (!button) return;

  const setThemeUi = (theme: 'dark' | 'light'): void => {
    root.dataset.theme = theme;
    button.textContent = theme === 'dark' ? '🌙' : '☀️';
    button.setAttribute('aria-label', theme === 'dark' ? 'Switch to light mode' : 'Switch to dark mode');
  };

  const initialTheme: 'dark' | 'light' = root.dataset.theme === 'light' ? 'light' : 'dark';
  setThemeUi(initialTheme);

  button.addEventListener('click', () => {
    const nextTheme: 'dark' | 'light' = root.dataset.theme === 'light' ? 'dark' : 'light';
    setThemeUi(nextTheme);
    localStorage.setItem('theme', nextTheme);
  });
}

async function runSelfTests(): Promise<void> {
  const checks = await Promise.all([
    runHmacSelfTest(),
    runCmacSelfTest(),
    Promise.resolve(runPoly1305SelfTest()),
    Promise.resolve(runGhashSelfTest()),
    runLengthExtensionSelfTest(),
    Promise.resolve(runTimingSelfTest())
  ]);

  if (checks.some((ok) => !ok)) {
    // Keep a visible signal in dev tools if an implementation drifts from known vectors.
    console.warn('One or more cryptographic self-tests failed.', checks);
  }
}

const app = document.querySelector<HTMLDivElement>('#app');
if (!app) throw new Error('Missing #app container');

renderApp(app);
wireThemeToggle();
void runSelfTests();
