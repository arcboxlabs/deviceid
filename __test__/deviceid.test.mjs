import assert from 'node:assert/strict';
import { mkdtempSync } from 'node:fs';
import { createRequire } from 'node:module';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';

const require = createRequire(import.meta.url);
const { ensureDeviceId } = require('../index.js');

const keysDir = mkdtempSync(join(tmpdir(), 'deviceid-test-'));
const options = { dir: keysDir, appName: 'deviceid-test' };

function pemToDer(pem) {
  const body = pem.replace(/-----(?:BEGIN|END) PUBLIC KEY-----|\s/g, '');
  return Buffer.from(body, 'base64');
}

// Mirrors how a server verifies device signatures (WebCrypto, SPKI import,
// P1363 signatures) — passing here proves wire-format compatibility.
async function verify(publicKeyPem, payload, signatureB64url) {
  const key = await crypto.subtle.importKey(
    'spki',
    pemToDer(publicKeyPem),
    { name: 'ECDSA', namedCurve: 'P-256' },
    false,
    ['verify'],
  );
  return crypto.subtle.verify(
    { name: 'ECDSA', hash: 'SHA-256' },
    key,
    Buffer.from(signatureB64url, 'base64url'),
    new TextEncoder().encode(payload),
  );
}

test('ensureDeviceId yields a well-formed identity', () => {
  const device = ensureDeviceId(options);
  assert.match(device.id, /^SHA256:[A-Za-z0-9+/]{43}$/);
  assert.match(device.publicKeyPem, /^-----BEGIN PUBLIC KEY-----\n[\s\S]+-----END PUBLIC KEY-----\n$/);
  assert.ok(['hardware', 'software'].includes(device.protection));
  console.log(`protection=${device.protection} id=${device.id}`);
});

test('the identity is idempotent across calls', () => {
  const first = ensureDeviceId(options);
  const second = ensureDeviceId(options);
  assert.equal(second.id, first.id);
  assert.equal(second.publicKeyPem, first.publicKeyPem);
});

test('signatures verify with WebCrypto and bind to the payload', async () => {
  const device = ensureDeviceId(options);
  const signature = device.sign('token-abc123');
  assert.equal(await verify(device.publicKeyPem, 'token-abc123', signature), true);
  assert.equal(await verify(device.publicKeyPem, 'token-tampered', signature), false);
});

test('signing twice yields fresh valid signatures', async () => {
  const device = ensureDeviceId(options);
  const one = device.sign('same-payload');
  const two = device.sign('same-payload');
  // ECDSA is randomized; both must verify regardless of equality.
  assert.equal(await verify(device.publicKeyPem, 'same-payload', one), true);
  assert.equal(await verify(device.publicKeyPem, 'same-payload', two), true);
});
