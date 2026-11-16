'use strict';

const crypto = require('node:crypto');
const { defineConfig, devices } = require('@playwright/test');

// Tokens are random per run and shared with the workers through the
// environment, so nothing secret-looking is committed.
process.env.PQCHAT_E2E_ALICE ||= crypto.randomBytes(32).toString('base64url');
process.env.PQCHAT_E2E_BOB ||= crypto.randomBytes(32).toString('base64url');

const PYTHON = process.env.PYTHON || (process.platform === 'win32' ? 'python' : 'python3');

const node = (name, p2pPort, uiPort, token) => ({
  command: `${PYTHON} -m pqchat --name ${name} --port ${p2pPort} --ui-port ${uiPort}`,
  url: `http://127.0.0.1:${uiPort}/`,
  env: { PQCHAT_UI_TOKEN: token },
  reuseExistingServer: false,
});

module.exports = defineConfig({
  testDir: './e2e',
  timeout: 30_000,
  workers: 1,
  reporter: [['list']],
  use: { trace: 'off' },
  projects: [{ name: 'chromium', use: { ...devices['Desktop Chrome'], viewport: { width: 1440, height: 900 } } }],
  // Two real nodes on loopback, each with its own UI.
  webServer: [
    node('alice', 9411, 8411, process.env.PQCHAT_E2E_ALICE),
    node('bob', 9412, 8412, process.env.PQCHAT_E2E_BOB),
  ],
});
