// Reuse the existing WebCrypto AES path; noble is an independent test oracle only.
export { aesBlockEncrypt } from '../cmac';
