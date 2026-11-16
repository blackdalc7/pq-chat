'use strict';

const { test, expect } = require('@playwright/test');

const ALICE = `http://127.0.0.1:8411/#token=${process.env.PQCHAT_E2E_ALICE}`;
const BOB = `http://127.0.0.1:8412/#token=${process.env.PQCHAT_E2E_BOB}`;

async function open(browser, url) {
  const context = await browser.newContext();
  const page = await context.newPage();
  // CSP violations surface as console errors: fail on them. Expected HTTP
  // error responses (a rejected card, for example) are not script errors.
  page.on('console', (msg) => {
    if (msg.type() === 'error' && !msg.text().startsWith('Failed to load resource')) {
      throw new Error(`console error: ${msg.text()}`);
    }
  });
  page.on('pageerror', (err) => {
    throw err;
  });
  await page.goto(url);
  await expect(page.getByTestId('node-status')).toContainText('online');
  return page;
}

async function send(page, text) {
  await page.getByTestId('message-input').fill(text);
  await page.getByTestId('send-button').click();
}

test.describe.configure({ mode: 'serial' });

test.describe('two nodes, two browsers', () => {
  let alice;
  let bob;

  test.beforeAll(async ({ browser }) => {
    alice = await open(browser, ALICE);
    bob = await open(browser, BOB);
  });

  test('token is stripped from the address bar', async () => {
    expect(alice.url()).toBe('http://127.0.0.1:8411/');
    await expect(alice.getByTestId('node-name')).toHaveText('alice');
    await expect(alice.getByTestId('hybrid-status')).toHaveText('No session');
  });

  test('rejects a mistyped contact card with a clear message', async () => {
    const card = await bob.getByTestId('own-card').innerText();
    // Change one character in the middle of the card.
    const typo = card[30] === 'A' ? 'B' : 'A';
    await alice.getByTestId('peer-card-input').fill(card.slice(0, 30) + typo + card.slice(31));
    await alice.getByTestId('connect-button').click();
    await expect(alice.getByTestId('connect-error')).toContainText('checksum mismatch');
  });

  test('connects with an out-of-band contact card', async () => {
    const card = await bob.getByTestId('own-card').innerText();
    expect(card).toMatch(/^pqchat1:[A-Za-z0-9_-]+$/);

    await alice.getByTestId('peer-card-input').fill(card);
    await alice.getByTestId('connect-button').click();

    for (const page of [alice, bob]) {
      await expect(page.getByTestId('chat')).toBeVisible();
      await expect(page.getByTestId('hybrid-status')).toHaveText('Hybrid PQ active');
      await expect(page.locator('[data-testid="algorithm"][data-active="true"]')).toHaveCount(4);
    }
    await expect(alice.getByTestId('crypto-panel')).toContainText('ML-KEM-768');
    await expect(alice.getByTestId('crypto-panel')).toContainText('pinned fingerprint');
    await expect(bob.getByTestId('crypto-panel')).toContainText('invite secret');
  });

  test('both sides show the same safety number', async () => {
    const a = await alice.getByTestId('safety-number').innerText();
    const b = await bob.getByTestId('safety-number').innerText();
    expect(a.replace(/\s/g, '')).toMatch(/^\d{60}$/);
    expect(a).toBe(b);
  });

  test('delivers messages in both directions', async () => {
    await send(alice, 'hello from alice');
    await expect(bob.getByTestId('message').last()).toContainText('hello from alice');
    await expect(bob.getByTestId('message').last()).toHaveAttribute('data-direction', 'in');

    await send(bob, 'hello from bob');
    await expect(alice.getByTestId('message').last()).toContainText('hello from bob');
    await expect(alice.getByTestId('message')).toHaveCount(2);
  });

  test('session key hash rolls forward with every sent message', async () => {
    const hash = alice.getByTestId('session-key-hash');
    const seen = new Set([await hash.innerText()]);
    for (const text of ['one', 'two', 'three']) {
      const before = await hash.innerText();
      await send(alice, text);
      await expect(hash).not.toHaveText(before);
      seen.add(await hash.innerText());
    }
    expect(seen.size).toBe(4);

    // Every message was encrypted under its own key.
    const tags = await alice.getByTestId('message-key').allInnerTexts();
    expect(new Set(tags).size).toBe(tags.length);
  });

  test('KEM ratchet advances when the conversation changes direction', async () => {
    const epoch = alice.getByTestId('ratchet-epoch');
    const root = alice.getByTestId('root-key-hash');
    const [epochBefore, rootBefore] = [Number(await epoch.innerText()), await root.innerText()];

    await send(bob, 'your turn');
    await expect(alice.getByTestId('message').last()).toContainText('your turn');

    await expect(epoch).not.toHaveText(String(epochBefore));
    expect(Number(await epoch.innerText())).toBeGreaterThan(epochBefore);
    await expect(root).not.toHaveText(rootBefore);
    await expect(alice.getByTestId('protocol-log')).toContainText('KEM ratchet step');
  });

  test('message content is rendered as text, never as markup', async () => {
    await send(alice, '<img src=x onerror="document.title=1337"><b>bold</b>');
    const last = bob.getByTestId('message').last();
    await expect(last).toContainText('<img src=x onerror=');
    expect(await last.locator('img, b').count()).toBe(0);
    expect(await bob.title()).toBe('PQ-Chat');
  });

  test('safety number can be marked as verified', async () => {
    await alice.getByTestId('verify-button').click();
    await expect(alice.getByTestId('verified-badge')).toBeVisible();
    await expect(alice.getByTestId('peer-item').first()).toContainText('verified');
  });

  test('revoking the invite changes the contact card', async () => {
    const before = await bob.getByTestId('own-card').innerText();
    await bob.getByTestId('rotate-invite').click();
    await expect(bob.getByTestId('own-card')).not.toHaveText(before);
    // The live session is unaffected.
    await send(alice, 'still here');
    await expect(bob.getByTestId('message').last()).toContainText('still here');
  });
});

test.describe('access control', () => {
  test('UI stays locked without a token', async ({ page }) => {
    await page.goto('http://127.0.0.1:8411/');
    await expect(page.getByTestId('locked')).toContainText('No access token');
  });

  test('UI locks when the token is wrong', async ({ page }) => {
    await page.goto(`http://127.0.0.1:8411/#token=${'x'.repeat(43)}`);
    await expect(page.getByTestId('locked')).toContainText('rejected');
  });

  test('API refuses unauthenticated and cross-origin calls', async ({ request }) => {
    expect((await request.get('http://127.0.0.1:8411/api/state')).status()).toBe(401);
    const crossOrigin = await request.get('http://127.0.0.1:8411/api/state', {
      headers: { authorization: `Bearer ${process.env.PQCHAT_E2E_ALICE}`, origin: 'https://attacker.example' },
    });
    expect(crossOrigin.status()).toBe(403);
    const csp = (await request.get('http://127.0.0.1:8411/')).headers()['content-security-policy'];
    expect(csp).toContain("default-src 'none'");
    expect(csp).not.toContain('unsafe');
  });
});
