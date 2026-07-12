import { describe, expect, it } from 'vitest';
import { resumeSha256FromDigest, sha256HexCore, sha256Pad } from './sha256core';

const enc = new TextEncoder();

async function webcryptoSha256Hex(data: Uint8Array): Promise<string> {
  const d = await crypto.subtle.digest('SHA-256', data);
  return Array.from(new Uint8Array(d), (b) => b.toString(16).padStart(2, '0')).join('');
}

describe('SHA-256 from-scratch core', () => {
  it('hashes the empty string to the NIST vector', () => {
    expect(sha256HexCore(new Uint8Array(0))).toBe(
      'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
    );
  });

  it('hashes "abc" to the NIST vector', () => {
    expect(sha256HexCore(enc.encode('abc'))).toBe(
      'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad'
    );
  });

  it('agrees with WebCrypto across many random lengths (incl. block boundaries)', async () => {
    for (const len of [0, 1, 55, 56, 63, 64, 65, 119, 120, 128, 200]) {
      const data = crypto.getRandomValues(new Uint8Array(len));
      expect(sha256HexCore(data)).toBe(await webcryptoSha256Hex(data));
    }
  });

  it('padding brings total length to a multiple of 64 bytes', () => {
    for (const len of [0, 1, 55, 56, 57, 63, 64, 120]) {
      expect((len + sha256Pad(len).length) % 64).toBe(0);
    }
  });
});

describe('length-extension resume primitive', () => {
  it('resuming from a digest reproduces the full re-hash (the forgery works)', async () => {
    // Victim computes tag = SHA-256(secret || message).
    const secret = enc.encode('SUPER-SECRET-KEY');
    const message = enc.encode('user=guest');
    const original = new Uint8Array(secret.length + message.length);
    original.set(secret, 0);
    original.set(message, secret.length);
    const originalTag = sha256HexCore(original);

    // Attacker (knows secret length, not secret) extends with "&admin=true".
    const append = enc.encode('&admin=true');
    const glue = sha256Pad(secret.length + message.length);
    const processedBefore = secret.length + message.length + glue.length;
    const forgedTag = resumeSha256FromDigest(originalTag, processedBefore, append);

    // Genuine tag the victim would compute for secret||message||glue||append.
    const forgedBody = new Uint8Array(message.length + glue.length + append.length);
    forgedBody.set(message, 0);
    forgedBody.set(glue, message.length);
    forgedBody.set(append, message.length + glue.length);
    const full = new Uint8Array(secret.length + forgedBody.length);
    full.set(secret, 0);
    full.set(forgedBody, secret.length);

    expect(forgedTag).toBe(sha256HexCore(full));
    expect(forgedTag).toBe(await webcryptoSha256Hex(full));
  });

  it('a WRONG guessed secret length yields a tag the server rejects', async () => {
    const secret = enc.encode('SUPER-SECRET-KEY'); // length 16
    const message = enc.encode('user=guest');
    const original = new Uint8Array(secret.length + message.length);
    original.set(secret, 0);
    original.set(message, secret.length);
    const originalTag = sha256HexCore(original);

    const append = enc.encode('&admin=true');
    const wrongLen = 8; // attacker guesses wrong
    const glue = sha256Pad(wrongLen + message.length);
    const processedBefore = wrongLen + message.length + glue.length;
    const forgedTag = resumeSha256FromDigest(originalTag, processedBefore, append);

    const forgedBody = new Uint8Array(message.length + glue.length + append.length);
    forgedBody.set(message, 0);
    forgedBody.set(glue, message.length);
    forgedBody.set(append, message.length + glue.length);
    const full = new Uint8Array(secret.length + forgedBody.length);
    full.set(secret, 0);
    full.set(forgedBody, secret.length);

    // Because the glue padding encodes the wrong length, the forged tag does
    // NOT match the true SHA-256(secret||forgedBody).
    expect(forgedTag).not.toBe(sha256HexCore(full));
  });
});
