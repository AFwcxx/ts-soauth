"use strict";

const SOAUTH_MAX_STORAGE_HOURS = 12;
const SOAUTH_INTENTIONS = Object.freeze(["register", "login"]);
const SOAUTH_CONTROLLERS = new Map();
const STORAGE_PREFIX = "soauth-";
const STORAGE_VERSION = 1;

const SOAUTH = {
  _sodium: null,
  sodium: null,
  fingerprint: null,
  hostId: null,
  hostEndpoint: null,
  hostSignPublicKey: null,
  hostBoxPublicKey: null,
  signKeypair: null,
  boxKeypair: null,
  boxSeed: null,
  token: null,
  expired_callback: null,
};

if (typeof window !== "undefined" && window.sodium) {
  SOAUTH._sodium = window.sodium;
}

if (!SOAUTH._sodium) {
  throw new Error("Libsodium not loaded.");
}

function isPlainObject(value) {
  return Object.prototype.toString.call(value) === "[object Object]";
}

function isNonEmptyString(value) {
  return typeof value === "string" && value.trim() !== "";
}

function serialize_message(message) {
  if (isPlainObject(message) || Array.isArray(message)) {
    return JSON.stringify(message);
  }

  if (typeof message === "string") {
    return message;
  }

  if (typeof message === "number" || typeof message === "boolean") {
    return String(message);
  }

  throw new Error("Invalid message format to serialize.");
}

function is_local_storage_available() {
  if (typeof window === "undefined" || !window.localStorage) {
    return false;
  }

  const testKey = "__soauth_test__";

  try {
    window.localStorage.setItem(testKey, testKey);
    window.localStorage.removeItem(testKey);
    return true;
  } catch (_error) {
    return false;
  }
}

function getStorageKey(hostSignPublicKey) {
  return `${STORAGE_PREFIX}${hostSignPublicKey}`;
}

function clearSensitiveState() {
  SOAUTH.hostBoxPublicKey = null;
  SOAUTH.signKeypair = null;
  SOAUTH.boxKeypair = null;
  SOAUTH.boxSeed = null;
  SOAUTH.token = null;
}

function validateHex(value, fieldName, expectedBytes = null) {
  if (!isNonEmptyString(value) || !/^[0-9a-f]+$/i.test(value) || value.length % 2 !== 0) {
    throw new Error(`Invalid ${fieldName} format.`);
  }

  if (expectedBytes !== null && value.length !== expectedBytes * 2) {
    throw new Error(`Invalid ${fieldName} length.`);
  }
}

function validateHostEndpoint(endpoint) {
  if (!isNonEmptyString(endpoint)) {
    throw new Error("Host endpoint not specified.");
  }

  let url;

  try {
    url = new URL(endpoint);
  } catch (_error) {
    throw new Error("Invalid host endpoint URL.");
  }

  if (url.protocol !== "https:" && url.protocol !== "http:") {
    throw new Error("Host endpoint must use http or https.");
  }

  const isLocalDevelopmentHost = ["localhost", "127.0.0.1", "[::1]"].includes(url.hostname);

  if (url.protocol !== "https:" && !isLocalDevelopmentHost) {
    throw new Error("Host endpoint must use HTTPS outside local development.");
  }

  return url.toString();
}

function normalizePathname(pathname = "") {
  if (pathname === "" || pathname == null) {
    return "";
  }

  if (typeof pathname !== "string") {
    throw new Error("Invalid pathname format.");
  }

  const trimmed = pathname.trim();

  if (!trimmed) {
    return "";
  }

  if (/^[a-z][a-z0-9+.-]*:/i.test(trimmed) || trimmed.startsWith("//")) {
    throw new Error("Absolute URLs are not allowed in pathname.");
  }

  return trimmed.startsWith("/") ? trimmed : `/${trimmed}`;
}

function parseTimestamp(value) {
  if (typeof value === "number" && Number.isFinite(value)) {
    return value;
  }

  if (typeof value === "string" && value.trim() !== "") {
    const numeric = Number(value);

    if (Number.isFinite(numeric)) {
      return numeric;
    }

    const parsed = Date.parse(value);

    if (!Number.isNaN(parsed)) {
      return parsed;
    }
  }

  return Number.NaN;
}

function isExpiredFingerprintResponse(response) {
  return (
    isPlainObject(response) &&
    typeof response.message === "string" &&
    response.message.toLowerCase().includes("expired fingerprint")
  );
}

function runExpiredCallback() {
  if (typeof SOAUTH.expired_callback === "function") {
    try {
      SOAUTH.expired_callback();
    } catch (_error) {
      // Avoid leaking callback failures through the auth path.
    }
  }
}

function handleExpiredFingerprint() {
  const currentHostSignPublicKey = SOAUTH.hostSignPublicKey;
  clearSensitiveState();
  clear_local_storage(currentHostSignPublicKey);
  runExpiredCallback();
}

async function ensureSodiumReady() {
  if (!SOAUTH._sodium) {
    throw new Error("Libsodium not loaded.");
  }

  await SOAUTH._sodium.ready;
  SOAUTH.sodium = SOAUTH._sodium;
  return SOAUTH.sodium;
}

async function captureFingerprint(webglProvider) {
  SOAUTH.fingerprint = null;

  if (typeof webglProvider !== "function") {
    return;
  }

  const result = await webglProvider();

  if (result && isNonEmptyString(result.fingerprint)) {
    SOAUTH.fingerprint = result.fingerprint;
  }
}

async function prepare_keypairs(credential) {
  await ensureSodiumReady();

  if (!isPlainObject(credential)) {
    throw new Error("Invalid credential format. Expecting object.");
  }

  let seedString = "";

  for (const key in credential) {
    if (Object.prototype.hasOwnProperty.call(credential, key)) {
      const hash = await SOAUTH.sodium.crypto_generichash(
        SOAUTH.sodium.crypto_generichash_BYTES_MAX,
        `${key}${credential[key]}`
      );

      seedString += SOAUTH.sodium.to_hex(hash);
    }
  }

  const seed = await SOAUTH.sodium.crypto_generichash(
    SOAUTH.sodium.crypto_generichash_BYTES_MAX,
    `${seedString}${SOAUTH.hostSignPublicKey}`
  );

  const signSeed = await SOAUTH.sodium.crypto_generichash(
    SOAUTH.sodium.crypto_sign_SEEDBYTES,
    seed
  );

  SOAUTH.boxSeed = await SOAUTH.sodium.crypto_generichash(
    SOAUTH.sodium.crypto_box_SEEDBYTES,
    `${seed}${SOAUTH.sodium.randombytes_random()}`
  );

  SOAUTH.signKeypair = await SOAUTH.sodium.crypto_sign_seed_keypair(signSeed);
  SOAUTH.boxKeypair = await SOAUTH.sodium.crypto_box_seed_keypair(SOAUTH.boxSeed);
}

async function send_message(message, pathname = "", requestId = "") {
  await ensureSodiumReady();

  if (!isNonEmptyString(SOAUTH.hostEndpoint)) {
    throw new Error("Host endpoint not configured.");
  }

  if (!isNonEmptyString(SOAUTH.fingerprint)) {
    throw new Error("Unable to capture device fingerprint.");
  }

  const url = new URL(SOAUTH.hostEndpoint);
  const normalizedPath = normalizePathname(pathname);
  const basePath = url.pathname.replace(/\/+$/, "");

  url.pathname = normalizedPath ? `${basePath}${normalizedPath}` : basePath || "/";

  const options = {
    method: "POST",
    headers: {
      Accept: "application/json",
      "Content-Type": "application/json",
      "SoAuth-Fingerprint": SOAUTH.fingerprint,
    },
    body: serialize_message(message),
    cache: "no-store",
    redirect: "error",
  };

  const hasRequestId = isNonEmptyString(requestId);

  if (hasRequestId) {
    const controller = new AbortController();
    SOAUTH_CONTROLLERS.set(requestId, controller);
    options.signal = controller.signal;
  }

  try {
    const response = await fetch(url.toString(), options);
    const rawBody = await response.text();

    let parsedBody = {};

    if (rawBody) {
      const contentType = response.headers.get("content-type") || "";

      if (!contentType.toLowerCase().includes("application/json")) {
        throw new Error("Unexpected response format from host.");
      }

      try {
        parsedBody = JSON.parse(rawBody);
      } catch (_error) {
        throw new Error("Invalid JSON response from host.");
      }
    }

    if (isExpiredFingerprintResponse(parsedBody)) {
      handleExpiredFingerprint();
    }

    if (!response.ok) {
      const safeMessage =
        parsedBody && typeof parsedBody.message === "string" && parsedBody.message.trim()
          ? parsedBody.message.trim()
          : `Request failed with status ${response.status}.`;

      throw new Error(safeMessage);
    }

    return parsedBody;
  } catch (error) {
    if (error && error.name === "AbortError") {
      return null;
    }

    throw error;
  } finally {
    if (hasRequestId) {
      SOAUTH_CONTROLLERS.delete(requestId);
    }
  }
}

const setup = async function (options = {}) {
  if (!isPlainObject(options)) {
    throw new Error("Invalid setup options.");
  }

  await ensureSodiumReady();

  if (!isNonEmptyString(options.hostId)) {
    throw new Error("Host ID not specified.");
  }

  if (!isNonEmptyString(options.hostSignPublicKey)) {
    throw new Error("Host signature public key not specified.");
  }

  validateHex(
    options.hostSignPublicKey,
    "hostSignPublicKey",
    SOAUTH.sodium.crypto_box_PUBLICKEYBYTES
  );

  SOAUTH.hostId = options.hostId.trim();
  SOAUTH.hostSignPublicKey = options.hostSignPublicKey;
  SOAUTH.hostEndpoint = validateHostEndpoint(options.hostEndpoint);
  SOAUTH.expired_callback =
    typeof options.expired_callback === "function" ? options.expired_callback : null;

  clearSensitiveState();
  await captureFingerprint(options.webgl);
};

const negotiate = async function (intention, credential, pathname, meta = {}) {
  await ensureSodiumReady();

  if (!SOAUTH_INTENTIONS.includes(intention)) {
    throw new Error("Invalid intention.");
  }

  if (!isPlainObject(credential)) {
    throw new Error("Invalid credential format. Expecting object.");
  }

  if (!isPlainObject(meta)) {
    throw new Error("Invalid meta format. Expecting object.");
  }

  await prepare_keypairs(credential);

  if (
    !SOAUTH.signKeypair ||
    !SOAUTH.signKeypair.publicKey ||
    !SOAUTH.signKeypair.privateKey ||
    !SOAUTH.boxKeypair ||
    !SOAUTH.boxKeypair.publicKey ||
    !SOAUTH.boxKeypair.privateKey
  ) {
    throw new Error("Invalid keypairs generated.");
  }

  const message = serialize_message({
    intention,
    meta,
    boxPublicKey: SOAUTH.sodium.to_hex(SOAUTH.boxKeypair.publicKey),
    serverSignPublicKey: SOAUTH.hostSignPublicKey,
  });

  const signedMessage = await SOAUTH.sodium.crypto_sign(
    SOAUTH.sodium.from_string(message),
    SOAUTH.signKeypair.privateKey
  );

  const signatureMessage = serialize_message({
    signature: SOAUTH.sodium.to_hex(signedMessage),
    signPublicKey: SOAUTH.sodium.to_hex(SOAUTH.signKeypair.publicKey),
  });

  const sealed = SOAUTH.sodium.crypto_box_seal(
    SOAUTH.sodium.from_string(signatureMessage),
    SOAUTH.sodium.from_hex(SOAUTH.hostSignPublicKey)
  );

  const response = await send_message(
    {
      sealed: SOAUTH.sodium.to_hex(sealed),
      hostId: SOAUTH.hostId,
    },
    pathname
  );

  if (response === null) {
    return null;
  }

  if (!isPlainObject(response)) {
    throw new Error("Invalid negotiation response from host.");
  }

  if (!isNonEmptyString(response.sealed)) {
    return false;
  }

  let extracted;

  try {
    extracted = await SOAUTH.sodium.crypto_box_seal_open(
      SOAUTH.sodium.from_hex(response.sealed),
      SOAUTH.boxKeypair.publicKey,
      SOAUTH.boxKeypair.privateKey
    );
  } catch (_error) {
    throw new Error("Invalid sealed response from host.");
  }

  if (!extracted) {
    throw new Error("Unable to extract host seal.");
  }

  let data;

  try {
    data = JSON.parse(SOAUTH.sodium.to_string(extracted));
  } catch (_error) {
    throw new Error("Invalid extracted host seal format.");
  }

  if (!isPlainObject(data)) {
    throw new Error("Invalid host data format.");
  }

  if (
    !isNonEmptyString(data.boxPublicKey) ||
    !isNonEmptyString(data.token) ||
    !isNonEmptyString(data.intention)
  ) {
    throw new Error("Invalid host data format.");
  }

  if (data.intention !== intention) {
    throw new Error("Invalid intention from host.");
  }

  validateHex(data.boxPublicKey, "boxPublicKey", SOAUTH.sodium.crypto_box_PUBLICKEYBYTES);

  SOAUTH.hostBoxPublicKey = SOAUTH.sodium.from_hex(data.boxPublicKey);
  SOAUTH.token = data.token;

  return data.token;
};

const exchange = async function (message, pathname, requestId = "") {
  await ensureSodiumReady();

  if (
    !SOAUTH.hostBoxPublicKey ||
    !SOAUTH.boxKeypair ||
    !SOAUTH.boxKeypair.publicKey ||
    !SOAUTH.boxKeypair.privateKey
  ) {
    throw new Error("Please negotiate with host first.");
  }

  if (!isNonEmptyString(SOAUTH.token)) {
    throw new Error("Missing session token.");
  }

  const serializedMessage = serialize_message(message);
  const nonce = SOAUTH.sodium.randombytes_buf(SOAUTH.sodium.crypto_box_NONCEBYTES);

  const ciphertext = await SOAUTH.sodium.crypto_box_easy(
    SOAUTH.sodium.from_string(serializedMessage),
    nonce,
    SOAUTH.hostBoxPublicKey,
    SOAUTH.boxKeypair.privateKey
  );

  const response = await send_message(
    {
      ciphertext: SOAUTH.sodium.to_hex(ciphertext),
      nonce: SOAUTH.sodium.to_hex(nonce),
      token: SOAUTH.token,
    },
    pathname,
    requestId
  );

  if (response === null) {
    return null;
  }

  if (
    !isPlainObject(response) ||
    !isNonEmptyString(response.ciphertext) ||
    !isNonEmptyString(response.nonce)
  ) {
    throw new Error("Invalid response format from host.");
  }

  let decrypted;

  try {
    decrypted = await SOAUTH.sodium.crypto_box_open_easy(
      SOAUTH.sodium.from_hex(response.ciphertext),
      SOAUTH.sodium.from_hex(response.nonce),
      SOAUTH.hostBoxPublicKey,
      SOAUTH.boxKeypair.privateKey
    );
  } catch (_error) {
    throw new Error("Invalid encrypted response from host.");
  }

  if (!decrypted) {
    throw new Error("Unable to decrypt information from host.");
  }

  const decoded = SOAUTH.sodium.to_string(decrypted);

  try {
    return JSON.parse(decoded);
  } catch (_error) {
    return decoded;
  }
};

function cancel_exchange(requestId) {
  if (!isNonEmptyString(requestId)) {
    return;
  }

  const controller = SOAUTH_CONTROLLERS.get(requestId);

  if (controller) {
    controller.abort();
    SOAUTH_CONTROLLERS.delete(requestId);
  }
}

async function deriveStorageKey(secret, saltHex = null) {
  await ensureSodiumReady();

  const secretIsString = typeof secret === "string" && secret.length > 0;
  const secretIsUint8Array = secret instanceof Uint8Array;

  if (!secretIsString && !secretIsUint8Array) {
    throw new Error("Invalid secret format.");
  }

  const canUsePwhash =
    typeof SOAUTH.sodium.crypto_pwhash === "function" &&
    typeof SOAUTH.sodium.crypto_pwhash_SALTBYTES === "number" &&
    typeof SOAUTH.sodium.crypto_pwhash_OPSLIMIT_INTERACTIVE === "number" &&
    typeof SOAUTH.sodium.crypto_pwhash_MEMLIMIT_INTERACTIVE === "number" &&
    typeof SOAUTH.sodium.crypto_pwhash_ALG_DEFAULT === "number";

  if (canUsePwhash) {
    let salt;

    if (saltHex !== null) {
      validateHex(saltHex, "salt", SOAUTH.sodium.crypto_pwhash_SALTBYTES);
      salt = SOAUTH.sodium.from_hex(saltHex);
    } else {
      salt = SOAUTH.sodium.randombytes_buf(SOAUTH.sodium.crypto_pwhash_SALTBYTES);
    }

    const key = SOAUTH.sodium.crypto_pwhash(
      SOAUTH.sodium.crypto_secretbox_KEYBYTES,
      secret,
      salt,
      SOAUTH.sodium.crypto_pwhash_OPSLIMIT_INTERACTIVE,
      SOAUTH.sodium.crypto_pwhash_MEMLIMIT_INTERACTIVE,
      SOAUTH.sodium.crypto_pwhash_ALG_DEFAULT
    );

    return {
      key,
      saltHex: SOAUTH.sodium.to_hex(salt),
    };
  }

  const key = await SOAUTH.sodium.crypto_generichash(
    SOAUTH.sodium.crypto_secretbox_KEYBYTES,
    secret
  );

  return {
    key,
    saltHex: null,
  };
}

function parseStoredEnvelope(payload) {
  if (!isNonEmptyString(payload)) {
    throw new Error("Invalid stored payload.");
  }

  const trimmed = payload.trim();

  if (trimmed.startsWith("{")) {
    const parsed = JSON.parse(trimmed);

    if (
      !isPlainObject(parsed) ||
      !isNonEmptyString(parsed.ciphertext) ||
      !isNonEmptyString(parsed.nonce)
    ) {
      throw new Error("Invalid stored payload.");
    }

    if (parsed.salt !== null && parsed.salt !== undefined && !isNonEmptyString(parsed.salt)) {
      throw new Error("Invalid stored payload.");
    }

    return {
      version: Number.isFinite(parsed.v) ? parsed.v : 0,
      ciphertext: parsed.ciphertext,
      nonce: parsed.nonce,
      salt: parsed.salt ?? null,
    };
  }

  const parts = trimmed.split(",");

  if (parts.length !== 2 || !isNonEmptyString(parts[0]) || !isNonEmptyString(parts[1])) {
    throw new Error("Invalid stored payload.");
  }

  return {
    version: 0,
    ciphertext: parts[0],
    nonce: parts[1],
    salt: null,
  };
}

const save = async function (secret, manual = false) {
  await ensureSodiumReady();

  if (!is_local_storage_available()) {
    manual = true;
  }

  if (
    !isNonEmptyString(SOAUTH.hostId) ||
    !isNonEmptyString(SOAUTH.hostEndpoint) ||
    !isNonEmptyString(SOAUTH.hostSignPublicKey) ||
    !SOAUTH.hostBoxPublicKey ||
    !SOAUTH.boxSeed ||
    !isNonEmptyString(SOAUTH.token)
  ) {
    throw new Error("No valid session state available to save.");
  }

  const store = {
    hostId: SOAUTH.hostId,
    hostEndpoint: SOAUTH.hostEndpoint,
    hostBoxPublicKey: SOAUTH.sodium.to_hex(SOAUTH.hostBoxPublicKey),
    boxSeed: SOAUTH.sodium.to_hex(SOAUTH.boxSeed),
    token: SOAUTH.token,
    ts: Date.now(),
  };

  const message = JSON.stringify(store);
  const { key, saltHex } = await deriveStorageKey(secret);
  const nonce = SOAUTH.sodium.randombytes_buf(SOAUTH.sodium.crypto_secretbox_NONCEBYTES);

  const ciphertext = SOAUTH.sodium.crypto_secretbox_easy(
    SOAUTH.sodium.from_string(message),
    nonce,
    key
  );

  const payload = JSON.stringify({
    v: STORAGE_VERSION,
    ciphertext: SOAUTH.sodium.to_hex(ciphertext),
    nonce: SOAUTH.sodium.to_hex(nonce),
    salt: saltHex,
  });

  if (manual) {
    return payload;
  }

  window.localStorage.setItem(getStorageKey(SOAUTH.hostSignPublicKey), payload);
};

const load = async function (secret, options = {}, data = false) {
  await ensureSodiumReady();

  if (!isPlainObject(options)) {
    throw new Error("Invalid load options.");
  }

  if (!isNonEmptyString(options.hostSignPublicKey)) {
    throw new Error("Expecting host signature public key in options.");
  }

  validateHex(
    options.hostSignPublicKey,
    "hostSignPublicKey",
    SOAUTH.sodium.crypto_box_PUBLICKEYBYTES
  );

  let encryptedPayload = data;
  let useLocalStorage = false;

  if (encryptedPayload === false) {
    if (!is_local_storage_available()) {
      return false;
    }

    useLocalStorage = true;
    encryptedPayload = window.localStorage.getItem(getStorageKey(options.hostSignPublicKey));

    if (!encryptedPayload) {
      return false;
    }
  }

  let parsedState;

  if (typeof encryptedPayload === "string") {
    let envelope;

    try {
      envelope = parseStoredEnvelope(encryptedPayload);
      const { key } = await deriveStorageKey(secret, envelope.salt);

      const decrypted = SOAUTH.sodium.crypto_secretbox_open_easy(
        SOAUTH.sodium.from_hex(envelope.ciphertext),
        SOAUTH.sodium.from_hex(envelope.nonce),
        key
      );

      parsedState = JSON.parse(SOAUTH.sodium.to_string(decrypted));
    } catch (_error) {
      return false;
    }
  } else if (isPlainObject(encryptedPayload)) {
    parsedState = encryptedPayload;
  } else {
    return false;
  }

  if (
    !isPlainObject(parsedState) ||
    !isNonEmptyString(parsedState.hostId) ||
    !isNonEmptyString(parsedState.hostEndpoint) ||
    !isNonEmptyString(parsedState.hostBoxPublicKey) ||
    !isNonEmptyString(parsedState.boxSeed) ||
    !isNonEmptyString(parsedState.token)
  ) {
    return false;
  }

  validateHex(parsedState.hostBoxPublicKey, "hostBoxPublicKey", SOAUTH.sodium.crypto_box_PUBLICKEYBYTES);
  validateHex(parsedState.boxSeed, "boxSeed", SOAUTH.sodium.crypto_box_SEEDBYTES);

  const storedAt = parseTimestamp(parsedState.ts);

  if (!Number.isFinite(storedAt)) {
    return false;
  }

  const maxAgeMs = SOAUTH_MAX_STORAGE_HOURS * 3600 * 1000;

  if (Date.now() - storedAt > maxAgeMs) {
    if (useLocalStorage) {
      clear_local_storage(options.hostSignPublicKey);
    }

    clearSensitiveState();
    SOAUTH.expired_callback =
      typeof options.expired_callback === "function" ? options.expired_callback : null;
    runExpiredCallback();
    return false;
  }

  try {
    SOAUTH.hostId = parsedState.hostId.trim();
    SOAUTH.hostEndpoint = validateHostEndpoint(parsedState.hostEndpoint);
    SOAUTH.hostSignPublicKey = options.hostSignPublicKey;
    SOAUTH.hostBoxPublicKey = SOAUTH.sodium.from_hex(parsedState.hostBoxPublicKey);
    SOAUTH.boxSeed = SOAUTH.sodium.from_hex(parsedState.boxSeed);
    SOAUTH.boxKeypair = SOAUTH.sodium.crypto_box_seed_keypair(SOAUTH.boxSeed);
    SOAUTH.signKeypair = null;
    SOAUTH.token = parsedState.token;
    SOAUTH.expired_callback =
      typeof options.expired_callback === "function" ? options.expired_callback : null;

    await captureFingerprint(options.webgl);
  } catch (_error) {
    clearSensitiveState();
    return false;
  }

  return true;
};

const clear_local_storage = function (hostSignPublicKey = SOAUTH.hostSignPublicKey) {
  if (!is_local_storage_available() || !isNonEmptyString(hostSignPublicKey)) {
    return;
  }

  window.localStorage.removeItem(getStorageKey(hostSignPublicKey));
};

export default {
  setup,
  negotiate,
  exchange,
  cancel_exchange,
  save,
  load,
  clear_local_storage,
};
