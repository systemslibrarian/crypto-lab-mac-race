/** A byte-level HMAC receiver with a fresh in-memory key per page session. */
export async function createHmacReceiver() {
  const secret = crypto.getRandomValues(new Uint8Array(32));
  const key = await crypto.subtle.importKey('raw', secret, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign', 'verify']);
  return {
    sign: async (bytes: Uint8Array): Promise<Uint8Array> => new Uint8Array(await crypto.subtle.sign('HMAC', key, bytes as BufferSource)),
    verify: (bytes: Uint8Array, tag: Uint8Array): Promise<boolean> => crypto.subtle.verify('HMAC', key, tag as BufferSource, bytes as BufferSource),
    // Only the explicitly opted-in leak branch calls this. No key is shown or stored.
    leakKeyForDemo: (): Uint8Array => secret.slice()
  };
}
