"use strict";

import _sodium from "libsodium-wrappers";
import { z } from "zod";

import { BoxKeyPair, EncryptResult } from "./interfaces/soauth.i";
import { hexString } from "./schemas/soauth";

// TODO: If this package moves to ESM/ES2022+, restore top-level await here
// in order to match the original import-time readiness semantics exactly.
const sodiumReady = _sodium.ready;
let sodiumInitialized = false;

void sodiumReady.then(() => {
  sodiumInitialized = true;
});

const SOAUTH_INTENTIONS = ["register", "login"] as const;

type SoauthIntention = (typeof SOAUTH_INTENTIONS)[number];

type AuthKeyPair = BoxKeyPair & {
  token: Uint8Array;
};

type StoreFieldType = "string" | "object";

type StoreFieldDefinition = {
  type: StoreFieldType;
  index: boolean;
};

type StoreDataDefinition = Record<string, StoreFieldDefinition>;

export type HostOptions = {
  secret: string;
  serves: string[];
};

export type NegotiateData = {
  intention: SoauthIntention;
  hostId: string;
  boxPublicKey: string;
  signPublicKey: string;
  meta: unknown;
  token: string;
};

export type NegotiateResponse = {
  success: boolean;
  message: string;
  sealed: string | null;
  data: NegotiateData | null;
};

export type HostInstance = {
  serialize_message: typeof serialize_message;
  negotiate: (request: unknown) => NegotiateResponse;
  verify_token: (
    hostId: unknown,
    boxPublicKey: unknown,
    token: unknown,
  ) => boolean;
  encrypt: (
    message: unknown,
    hostId: unknown,
    boxPublicKey: unknown,
  ) => EncryptResult;
  decrypt: (
    data: unknown,
    hostId: unknown,
    boxPublicKey: unknown,
  ) => unknown | false;
  get_box_pubkey: (hostId: unknown, boxPublicKey: unknown) => string;
  check_store_data: typeof check_store_data;
  SOAUTH_HUMAN_STOREDATA: typeof SOAUTH_HUMAN_STOREDATA;
  SOAUTH_MACHINE_STOREDATA: typeof SOAUTH_MACHINE_STOREDATA;
};

const SecretSchema = z.preprocess(
  (value) => {
    if (!value) {
      return value;
    }

    return String(value);
  },
  z.string().min(1),
);

const ServesSchema = z.array(z.string()).min(1);

const NegotiationEnvelopeSchema = z.looseObject({
  sealed: hexString({ maxBytes: 16_384 }),
  hostId: z.string().min(1).max(255),
});

const NegotiationPayloadSchema = z.looseObject({
  signature: hexString({ maxBytes: 16_384 }),
  signPublicKey: hexString({ exactBytes: 32 }),
});

const SignedMessageSchema = z.looseObject({
  intention: z.enum(SOAUTH_INTENTIONS),
  boxPublicKey: hexString({ exactBytes: 32 }),
  serverSignPublicKey: hexString({ exactBytes: 32 }),
  meta: z.unknown().optional(),
});

const StoreFieldDefinitionSchema = z.object({
  type: z.enum(["string", "object"]),
  index: z.boolean(),
});

const StoreDataDefinitionSchema = z.record(
  z.string(),
  StoreFieldDefinitionSchema,
);

const StringBoxPublicKeyParamsSchema = z.object({
  hostId: z.string(),
  boxPublicKey: z.string(),
});

const BoxPublicKeyInputSchema = z.union([z.string(), z.instanceof(Uint8Array)]);

const VerifyTokenParamsSchema = z.object({
  hostId: z.string(),
  boxPublicKey: BoxPublicKeyInputSchema,
  token: z.string(),
});

const GetBoxPubkeyParamsSchema = z.object({
  hostId: z.string(),
  boxPublicKey: BoxPublicKeyInputSchema,
});

const DecryptEnvelopeSchema = z.looseObject({
  ciphertext: hexString({ maxBytes: 64_000 }),
  nonce: hexString({ exactBytes: 24 }),
  token: hexString({ exactBytes: 64 }),
});

type DecryptEnvelope = z.infer<typeof DecryptEnvelopeSchema>;

function parseBoundary<T>(
  schema: z.ZodType<T>,
  value: unknown,
  errorMessage: string,
): T {
  const parsed = schema.safeParse(value);

  if (!parsed.success) {
    throw new Error(errorMessage);
  }

  return parsed.data;
}

function isUint8Array(value: unknown): value is Uint8Array {
  return value instanceof Uint8Array;
}

function isObjectLike(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}

function getSodium(): typeof _sodium {
  if (!sodiumInitialized) {
    throw new Error("SoAuth: libsodium is not ready yet.");
  }

  return _sodium;
}

function normalizeBoxPublicKey(
  sodium: typeof _sodium,
  boxPublicKey: string | Uint8Array,
): string {
  if (isUint8Array(boxPublicKey)) {
    return sodium.to_hex(boxPublicKey);
  }

  return boxPublicKey;
}

export const serialize_message = function (message: unknown): string {
  if (typeof message === "object") {
    const serialized = JSON.stringify(message);

    if (typeof serialized !== "string") {
      throw new Error("Invalid message format to serialize");
    }

    return serialized;
  }

  if (typeof message === "string") {
    return message;
  }

  if (typeof message === "number") {
    return String(message);
  }

  throw new Error("Invalid message format to serialize");
};

export const SOAUTH_HUMAN_STOREDATA = {
  hostId: {
    type: "string",
    index: true,
  },
  signPublicKey: {
    type: "string",
    index: true,
  },
  boxPublicKey: {
    type: "string",
    index: false,
  },
  meta: {
    type: "object",
    index: false,
  },
  token: {
    type: "string",
    index: false,
  },
  fingerprint: {
    type: "string",
    index: false,
  },
} as const satisfies StoreDataDefinition;

export const SOAUTH_MACHINE_STOREDATA = {
  hostId: {
    type: "string",
    index: true,
  },
  fingerprint: {
    type: "string",
    index: true,
  },
  publicKey: {
    type: "string",
    index: false,
  },
} as const satisfies StoreDataDefinition;

function matchesStoreFieldType(
  expectedType: StoreFieldType,
  value: unknown,
): boolean {
  return typeof value === expectedType;
}

export const check_store_data = function (
  SOAUTH_STOREDATA: unknown,
  data: unknown,
): boolean {
  if (typeof data !== "object" || data === null) {
    throw new Error("SoAuth: Invalid store data format.");
  }

  const storeDataDefinition = parseBoundary(
    StoreDataDefinitionSchema,
    SOAUTH_STOREDATA,
    "SoAuth: Invalid SOAUTH_STOREDATA data format.",
  );

  let pass = true;
  const dataRecord = data as Record<string, unknown>;

  for (const k in storeDataDefinition) {
    if (Object.prototype.hasOwnProperty.call(storeDataDefinition, k)) {
      if (!matchesStoreFieldType(storeDataDefinition[k].type, dataRecord[k])) {
        pass = false;
        console.log(`SoAuth: Missing or invalid ${k} format in store data.`);
        break;
      }
    }
  }

  return pass;
};

type InitializedHost = {
  host: HostInstance;
  signingPublicKeys: readonly [string, string][];
};

function initializeHost(
  options: unknown = {},
  enforceServedHostIds = true,
): InitializedHost {
  const sodium = getSodium();
  const optionBag = isObjectLike(options) ? options : {};
  const secret = parseBoundary(
    SecretSchema,
    optionBag.secret,
    "SoAuth: Invalid secret format.",
  );
  const serves = Object.freeze([
    ...parseBoundary(
      ServesSchema,
      optionBag.serves,
      "SoAuth: Invalid serves format.",
    ),
  ]);
  const servedHostIds = new Set(serves);

  function assertServedHostId(hostId: string): void {
    if (!servedHostIds.has(hostId)) {
      throw new Error("SoAuth: Host id is not served.");
    }
  }

  function generateSign(hostId: string): BoxKeyPair {
    const seed = sodium.crypto_generichash(
      sodium.crypto_generichash_BYTES_MAX,
      secret + hostId,
    );
    const signSeed = sodium.crypto_generichash(sodium.crypto_box_SEEDBYTES, seed);

    return sodium.crypto_box_seed_keypair(signSeed);
  }

  function generateAuth(
    hostId: string,
    boxPublicKey: string | Uint8Array,
  ): AuthKeyPair {
    const normalizedBoxPublicKey = normalizeBoxPublicKey(sodium, boxPublicKey);
    const seed = sodium.crypto_generichash(
      sodium.crypto_generichash_BYTES_MAX,
      secret + hostId + normalizedBoxPublicKey,
    );
    const boxSeed = sodium.crypto_generichash(sodium.crypto_box_SEEDBYTES, seed);
    const boxKeypair = sodium.crypto_box_seed_keypair(boxSeed);

    return {
      ...boxKeypair,
      token: sodium.crypto_generichash(
        sodium.crypto_generichash_BYTES_MAX,
        sodium.to_hex(boxKeypair.publicKey) + hostId,
      ),
    };
  }

  const negotiate = function (request: unknown): NegotiateResponse {
    const response: NegotiateResponse = {
      success: false,
      message: "Invalid request",
      sealed: null,
      data: null,
    };

    try {
      const negotiationEnvelope = parseBoundary(
        NegotiationEnvelopeSchema,
        request,
        "Invalid request format.",
      );
      const hostId = negotiationEnvelope.hostId;

      assertServedHostId(hostId);

      const sign = generateSign(hostId);
      const openedSeal = sodium.crypto_box_seal_open(
        sodium.from_hex(negotiationEnvelope.sealed),
        sign.publicKey,
        sign.privateKey,
      );
      const parsedNegotiation = parseBoundary(
        NegotiationPayloadSchema,
        JSON.parse(sodium.to_string(openedSeal)) as unknown,
        "Invalid negotiation format.",
      );
      const signature = sodium.from_hex(parsedNegotiation.signature);
      const signPublicKey = sodium.from_hex(parsedNegotiation.signPublicKey);
      const extracted = sodium.crypto_sign_open(signature, signPublicKey);

      if (!extracted) {
        throw new Error("Invalid request signature.");
      }

      const message = parseBoundary(
        SignedMessageSchema,
        JSON.parse(sodium.to_string(extracted)) as unknown,
        "Invalid signed message format.",
      );

      if (message.serverSignPublicKey !== sodium.to_hex(sign.publicKey)) {
        throw new Error("Invalid host signature requested.");
      }

      const auth = generateAuth(hostId, message.boxPublicKey);
      const serialized = serialize_message({
        intention: message.intention,
        boxPublicKey: sodium.to_hex(auth.publicKey),
        token: sodium.to_hex(auth.token),
      });
      const sealed = sodium.crypto_box_seal(
        serialized,
        sodium.from_hex(message.boxPublicKey),
      );

      response.data = {
        intention: message.intention,
        hostId,
        boxPublicKey: message.boxPublicKey,
        signPublicKey: sodium.to_hex(signPublicKey),
        meta: message.meta,
        token: sodium.to_hex(auth.token),
      };
      response.sealed = sodium.to_hex(sealed);
    } catch {
      return response;
    }

    response.success = true;
    response.message = "OK";

    return response;
  };

  const verify_token = function (
    hostId: unknown,
    boxPublicKey: unknown,
    token: unknown,
  ): boolean {
    const parsed = parseBoundary(
      VerifyTokenParamsSchema,
      { hostId, boxPublicKey, token },
      "SoAuth: Invalid verify_token parameters.",
    );

    if (enforceServedHostIds && !servedHostIds.has(parsed.hostId)) {
      return false;
    }

    const auth = generateAuth(parsed.hostId, parsed.boxPublicKey);
    let providedToken: Uint8Array;

    try {
      providedToken = sodium.from_hex(parsed.token);
    } catch {
      return false;
    }

    return (
      auth.token.length === providedToken.length &&
      sodium.memcmp(auth.token, providedToken)
    );
  };

  const encrypt = function (
    message: unknown,
    hostId: unknown,
    boxPublicKey: unknown,
  ): EncryptResult {
    const parsed = parseBoundary(
      StringBoxPublicKeyParamsSchema,
      { hostId, boxPublicKey },
      "Expecting boxPublicKey to be string.",
    );

    if (enforceServedHostIds) {
      assertServedHostId(parsed.hostId);
    }

    const peerBoxPublicKey = sodium.from_hex(parsed.boxPublicKey);
    const serialized = serialize_message(message);
    const auth = generateAuth(parsed.hostId, peerBoxPublicKey);
    const nonce = sodium.randombytes_buf(sodium.crypto_box_NONCEBYTES);
    const ciphertext = sodium.crypto_box_easy(
      serialized,
      nonce,
      peerBoxPublicKey,
      auth.privateKey,
    );

    return {
      ciphertext: sodium.to_hex(ciphertext),
      nonce: sodium.to_hex(nonce),
    };
  };

  const decrypt = function (
    data: unknown,
    hostId: unknown,
    boxPublicKey: unknown,
  ): unknown | false {
    const parsedDataResult = DecryptEnvelopeSchema.safeParse(data);

    if (!parsedDataResult.success) {
      return false;
    }

    const parsedKeyResult = StringBoxPublicKeyParamsSchema.safeParse({
      hostId,
      boxPublicKey,
    });

    if (!parsedKeyResult.success) {
      throw new Error("Expecting boxPublicKey to be string.");
    }

    const parsedData: DecryptEnvelope = parsedDataResult.data;
    const parsedKey = parsedKeyResult.data;

    if (enforceServedHostIds && !servedHostIds.has(parsedKey.hostId)) {
      return false;
    }

    if (!verify_token(parsedKey.hostId, parsedKey.boxPublicKey, parsedData.token)) {
      return false;
    }

    try {
      const auth = generateAuth(parsedKey.hostId, parsedKey.boxPublicKey);
      const decrypted = sodium.crypto_box_open_easy(
        sodium.from_hex(parsedData.ciphertext),
        sodium.from_hex(parsedData.nonce),
        sodium.from_hex(parsedKey.boxPublicKey),
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

  const get_box_pubkey = function (
    hostId: unknown,
    boxPublicKey: unknown,
  ): string {
    const parsed = parseBoundary(
      GetBoxPubkeyParamsSchema,
      { hostId, boxPublicKey },
      "SoAuth: Invalid get_box_pubkey parameters.",
    );

    if (enforceServedHostIds) {
      assertServedHostId(parsed.hostId);
    }

    return sodium.to_hex(generateAuth(parsed.hostId, parsed.boxPublicKey).publicKey);
  };

  const host: HostInstance = Object.freeze({
    serialize_message,
    negotiate,
    verify_token,
    encrypt,
    decrypt,
    get_box_pubkey,
    check_store_data,
    SOAUTH_HUMAN_STOREDATA,
    SOAUTH_MACHINE_STOREDATA,
  });

  return {
    host,
    signingPublicKeys: serves.map(
      (hostId): [string, string] => [
        hostId,
        sodium.to_hex(generateSign(hostId).publicKey),
      ],
    ),
  };
}

/**
 * Creates an isolated Host whose secret and served host IDs are private to the
 * returned instance. A host ID must be listed in `serves` for instance methods
 * that derive or verify credentials.
 */
export function createHost(options: HostOptions): HostInstance {
  return initializeHost(options).host;
}

let legacyHost: HostInstance | null = null;

function getLegacyHost(): HostInstance {
  if (legacyHost === null) {
    throw new Error("SoAuth: Please run setup first.");
  }

  return legacyHost;
}

export const setup = function (options: unknown = {}): void {
  legacyHost = null;
  const initialized = initializeHost(options, false);
  legacyHost = initialized.host;

  for (const [hostId, publicKey] of initialized.signingPublicKeys) {
    console.log("Signature public key for " + hostId + " is", publicKey);
  }
};

export const negotiate = function (request: unknown): NegotiateResponse {
  return getLegacyHost().negotiate(request);
};

export const verify_token = function (
  hostId: unknown,
  boxPublicKey: unknown,
  token: unknown,
): boolean {
  return getLegacyHost().verify_token(hostId, boxPublicKey, token);
};

export const encrypt = function (
  message: unknown,
  hostId: unknown,
  boxPublicKey: unknown,
): EncryptResult {
  return getLegacyHost().encrypt(message, hostId, boxPublicKey);
};

export const decrypt = function (
  data: unknown,
  hostId: unknown,
  boxPublicKey: unknown,
): unknown | false {
  return getLegacyHost().decrypt(data, hostId, boxPublicKey);
};

export const get_box_pubkey = function (
  hostId: unknown,
  boxPublicKey: unknown,
): string {
  return getLegacyHost().get_box_pubkey(hostId, boxPublicKey);
};

const Host = {
  setup,
  serialize_message,
  negotiate,
  verify_token,
  SOAUTH_HUMAN_STOREDATA,
  SOAUTH_MACHINE_STOREDATA,
  check_store_data,
  encrypt,
  decrypt,
  get_box_pubkey,
};

export default Host;
