"use strict";

import _sodium from "libsodium-wrappers";

export type BoxKeyPair = {
  publicKey: Uint8Array;
  privateKey: Uint8Array;
};

export type SoAuthState = {
  sodium: typeof _sodium;
  secret: string | false;
  hostId?: string | false;
  hostPublicKey?: Uint8Array | false;
  serves?: string[] | false;
};

export type EncryptResult = {
  ciphertext: string;
  nonce: string;
};
