import '../styles/main.css';

import { runCmacSelfTest } from './cmac';
import { runGhashSelfTest } from './ghash';
import { runHmacSelfTest } from './hmac';
import { runLengthExtensionSelfTest } from './lengthext';
import { runPoly1305SelfTest } from './poly1305';
import { runTimingSelfTest } from './timing';
import { renderApp } from './ui';

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

document.documentElement.dataset.theme = 'dark';
renderApp(app);
void runSelfTests();
