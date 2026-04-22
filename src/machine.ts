"use strict";

import os from "node:os";
import _sodium from "libsodium-wrappers";
import { z } from "zod";

import { BoxKeyPair, SoAuthState, EncryptResult } from "./interfaces/soauth.i";
import { hexString } from "./schemas/soauth";

// TODO: If this package moves to ESM/ES2022+, restore top-level await
// to match the original import-time readiness semantics exactly.
const sodiumReady: Promise<unknown> = _sodium.ready;
let sodiumInitialized = false;

void sodiumReady.then(() => {
  sodiumInitialized = true;
});

const coerceNonEmptyString = (value: unknown): unknown => {
  if (!value) {
    return value;
  }

  return String(value);
};


const SetupOptionsSchema = z.object({
  secret: z.preprocess(coerceNonEmptyString, z.string().min(1)).optional(),
  hostId: z.preprocess(coerceNonEmptyString, z.string().min(1)).optional(),
  hostPublicKey: z
    .preprocess(coerceNonEmptyString, hexString({ exactBytes: 32 }))
    .optional(),
});

const DecryptPayloadSchema = z.object({
  ciphertext: hexString({ minBytes: 1 }),
  nonce: hexString({ exactBytes: 24 }),
});

type SetupOptions = z.infer<typeof SetupOptionsSchema>;
// type DecryptPayload = z.infer<typeof DecryptPayloadSchema>;


type CpuData = {
  cores?: number;
  models?: string[];
};

type FingerprintInformation = {
  os: string;
  user: ReturnType<typeof os.userInfo>;
  architecture: string;
  cpu: CpuData;
  endianness: ReturnType<typeof os.endianness>;
  hostname: string;
  machine: string;
  network: string;
  platform: NodeJS.Platform;
  memory: number;
};

const SOAUTH: SoAuthState = {
  sodium: _sodium,
  secret: false,
  hostId: false,
  hostPublicKey: false,
};

function getSodium(): typeof _sodium {
  if (!sodiumInitialized) {
    throw new Error("SoAuth: libsodium is not ready yet.");
  }

  return SOAUTH.sodium;
}

function getConfiguredHostId(): string {
  if (!SOAUTH.hostId) {
    throw new Error("SoAuth: Please run setup first.");
  }

  return SOAUTH.hostId;
}

function getConfiguredHostPublicKey(): Uint8Array {
  if (!SOAUTH.hostPublicKey) {
    throw new Error("SoAuth: Please run setup first.");
  }

  return SOAUTH.hostPublicKey;
}

function generate_auth(hostId: string): BoxKeyPair {
  const sodium = getSodium();

  if (!SOAUTH.secret) {
    throw new Error("SoAuth: Invalid secret format.");
  }

  const seed = sodium.crypto_generichash(
    sodium.crypto_generichash_BYTES_MAX,
    SOAUTH.secret + hostId,
  );
  const boxSeed = sodium.crypto_generichash(
    sodium.crypto_box_SEEDBYTES,
    seed,
  );
  const boxKeypair = sodium.crypto_box_seed_keypair(boxSeed);

  return boxKeypair;
}

export const serialize_message = function (message: unknown): string {
  if (typeof message === "object") {
    return JSON.stringify(message);
  }

  if (typeof message === "string") {
    return message;
  }

  if (typeof message === "number") {
    return String(message);
  }

  throw new Error("Invalid message format to serialize");
};

export const get_pubkey = function (): string {
  const hostId = getConfiguredHostId();
  const auth = generate_auth(hostId);

  return getSodium().to_hex(auth.publicKey);
};

export const setup = function (options: unknown = {}): void {
  const parsedOptionsResult = SetupOptionsSchema.safeParse(options);
  const parsedOptions: Partial<SetupOptions> = parsedOptionsResult.success
    ? parsedOptionsResult.data
    : {};

  SOAUTH.secret = parsedOptions.secret ?? false;
  SOAUTH.hostId = parsedOptions.hostId ?? false;
  SOAUTH.hostPublicKey = false;

  if (!SOAUTH.secret) {
    throw new Error("SoAuth: Invalid secret format.");
  }

  if (!SOAUTH.hostId) {
    throw new Error("SoAuth: Invalid host id format.");
  }

  if (!parsedOptions.hostPublicKey) {
    throw new Error("SoAuth: Invalid host public key format.");
  }

  SOAUTH.hostPublicKey = getSodium().from_hex(parsedOptions.hostPublicKey);

  console.log("Public key is", get_pubkey());
};

export const encrypt = function (message: unknown): EncryptResult {
  const hostId = getConfiguredHostId();
  const hostPublicKey = getConfiguredHostPublicKey();
  const sodium = getSodium();

  const serialized = serialize_message(message);
  const auth = generate_auth(hostId);
  const nonce = sodium.randombytes_buf(sodium.crypto_box_NONCEBYTES);
  const ciphertext = sodium.crypto_box_easy(
    serialized,
    nonce,
    hostPublicKey,
    auth.privateKey,
  );

  return {
    ciphertext: sodium.to_hex(ciphertext),
    nonce: sodium.to_hex(nonce),
  };
};

export const decrypt = function (data: unknown): unknown | false {
  const parsedDataResult = DecryptPayloadSchema.safeParse(data);

  if (!parsedDataResult.success) {
    return false;
  }

  const hostId = getConfiguredHostId();
  const hostPublicKey = getConfiguredHostPublicKey();
  const sodium = getSodium();
  const auth = generate_auth(hostId);

  try {
    const decrypted = sodium.crypto_box_open_easy(
      sodium.from_hex(parsedDataResult.data.ciphertext),
      sodium.from_hex(parsedDataResult.data.nonce),
      hostPublicKey,
      auth.privateKey,
    );

    if (!decrypted) {
      return false;
    }

    const message = sodium.to_string(decrypted);

    try {
      return JSON.parse(message) as unknown;
    } catch {
      return message;
    }
  } catch {
    return false;
  }
};

export function fingerprint(raw: true): FingerprintInformation;
export function fingerprint(raw?: false): string;
export function fingerprint(raw = false): FingerprintInformation | string {
  const cpuData: CpuData = {};
  const cpus = os.cpus();

  if (Array.isArray(cpus)) {
    cpuData.cores = cpus.length;
    cpuData.models = cpus.map((cpu) => cpu.model);
  }

  const information: FingerprintInformation = {
    os: os.type(),
    user: os.userInfo(),
    architecture: os.arch(),
    cpu: cpuData,
    endianness: os.endianness(),
    hostname: os.hostname(),
    machine: os.machine(),
    network: JSON.stringify(os.networkInterfaces()),
    platform: os.platform(),
    memory: os.totalmem(),
  };

  if (raw) {
    return information;
  }

  const buffer = getSodium().crypto_generichash(
    getSodium().crypto_generichash_BYTES_MAX,
    JSON.stringify(information),
  );

  return getSodium().to_hex(buffer);
}

export default {
  serialize_message,
  setup,
  get_pubkey,
  encrypt,
  decrypt,
  fingerprint,
};
