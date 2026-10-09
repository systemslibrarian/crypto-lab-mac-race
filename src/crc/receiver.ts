import { crc32 } from './crc32';

/** The one receiver used for every checksum verdict in the lesson. */
export function crcReceiverAccepts(bytes: Uint8Array, sentCrc: number): boolean {
  return crc32(bytes) === (sentCrc >>> 0);
}
