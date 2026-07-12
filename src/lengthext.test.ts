import { describe, expect, it } from 'vitest';
import {
  attemptForge,
  captureOriginalRequest,
  getActualSecretLength,
  hmacServerVerify,
  rawServerVerify,
  regenerateDemoSecret,
  runLengthExtensionSelfTest,
} from './lengthext';

const enc = new TextEncoder();

describe('SHA-256(secret||message) length-extension attack', () => {
  it('self-test forges a valid tag without the secret', async () => {
    expect(await runLengthExtensionSelfTest()).toBe(true);
  });

  it('with the CORRECT guessed secret length, the raw server accepts the forgery', async () => {
    const len = regenerateDemoSecret();
    const message = 'amount=10&to=alice';
    const { rawMacHex, hmacMacHex } = await captureOriginalRequest(message);

    const forge = await attemptForge(message, rawMacHex, hmacMacHex, '&to=attacker', len);
    expect(forge.guessCorrect).toBe(true);
    expect(forge.rawServerAccepts).toBe(true);
  });

  it('the same technique FAILS against the HMAC server (not length-extensible)', async () => {
    const len = getActualSecretLength();
    const message = 'amount=10&to=alice';
    const { rawMacHex, hmacMacHex } = await captureOriginalRequest(message);

    const forge = await attemptForge(message, rawMacHex, hmacMacHex, '&to=attacker', len);
    // Even with the correct length, HMAC's outer hash defeats the extension.
    expect(forge.hmacServerAccepts).toBe(false);
  });

  it('a WRONG guessed length is rejected by the raw server', async () => {
    const len = getActualSecretLength();
    const wrong = len === 24 ? len - 1 : len + 1;
    const message = 'amount=10&to=alice';
    const { rawMacHex, hmacMacHex } = await captureOriginalRequest(message);

    const forge = await attemptForge(message, rawMacHex, hmacMacHex, '&to=attacker', wrong);
    expect(forge.guessCorrect).toBe(false);
    expect(forge.rawServerAccepts).toBe(false);
  });

  it('rawServerVerify rejects a tampered message under a genuine tag', async () => {
    const message = 'balance=0';
    const { rawMacHex } = await captureOriginalRequest(message);
    // Genuine tag but for the wrong message bytes → rejected.
    expect(await rawServerVerify(enc.encode('balance=9'), rawMacHex)).toBe(false);
  });

  it('hmacServerVerify accepts only its own genuine tag', async () => {
    const message = 'x=1';
    const { hmacMacHex } = await captureOriginalRequest(message);
    expect(await hmacServerVerify(enc.encode(message), hmacMacHex)).toBe(true);
    expect(await hmacServerVerify(enc.encode('x=2'), hmacMacHex)).toBe(false);
  });
});
