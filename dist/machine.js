"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.decrypt = exports.encrypt = exports.setup = exports.get_pubkey = exports.serialize_message = void 0;
exports.fingerprint = fingerprint;
const node_os_1 = __importDefault(require("node:os"));
const libsodium_wrappers_1 = __importDefault(require("libsodium-wrappers"));
const zod_1 = require("zod");
const sodiumReady = libsodium_wrappers_1.default.ready;
let sodiumInitialized = false;
void sodiumReady.then(() => {
    sodiumInitialized = true;
});
const HEX_REGEX = /^[0-9a-f]+$/i;
const coerceNonEmptyString = (value) => {
    if (!value) {
        return value;
    }
    return String(value);
};
function hexString(options) {
    let schema = zod_1.z
        .string()
        .regex(HEX_REGEX, "Invalid hex format")
        .refine((value) => value.length % 2 === 0, "Invalid hex length");
    if (typeof options?.exactBytes === "number") {
        schema = schema.length(options.exactBytes * 2);
    }
    if (typeof options?.minBytes === "number") {
        schema = schema.min(options.minBytes * 2);
    }
    if (typeof options?.maxBytes === "number") {
        schema = schema.max(options.maxBytes * 2);
    }
    return schema;
}
const SetupOptionsSchema = zod_1.z.object({
    secret: zod_1.z.preprocess(coerceNonEmptyString, zod_1.z.string().min(1)).optional(),
    hostId: zod_1.z.preprocess(coerceNonEmptyString, zod_1.z.string().min(1)).optional(),
    hostPublicKey: zod_1.z
        .preprocess(coerceNonEmptyString, hexString({ exactBytes: 32 }))
        .optional(),
});
const DecryptPayloadSchema = zod_1.z.object({
    ciphertext: hexString({ minBytes: 1 }),
    nonce: hexString({ exactBytes: 24 }),
});
const SOAUTH = {
    sodium: libsodium_wrappers_1.default,
    secret: false,
    hostId: false,
    hostPublicKey: false,
};
function getSodium() {
    if (!sodiumInitialized) {
        throw new Error("SoAuth: libsodium is not ready yet.");
    }
    return SOAUTH.sodium;
}
function getConfiguredHostId() {
    if (!SOAUTH.hostId) {
        throw new Error("SoAuth: Please run setup first.");
    }
    return SOAUTH.hostId;
}
function getConfiguredHostPublicKey() {
    if (!SOAUTH.hostPublicKey) {
        throw new Error("SoAuth: Please run setup first.");
    }
    return SOAUTH.hostPublicKey;
}
function generate_auth(hostId) {
    const sodium = getSodium();
    if (!SOAUTH.secret) {
        throw new Error("SoAuth: Invalid secret format.");
    }
    const seed = sodium.crypto_generichash(sodium.crypto_generichash_BYTES_MAX, SOAUTH.secret + hostId);
    const boxSeed = sodium.crypto_generichash(sodium.crypto_box_SEEDBYTES, seed);
    const boxKeypair = sodium.crypto_box_seed_keypair(boxSeed);
    return boxKeypair;
}
const serialize_message = function (message) {
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
exports.serialize_message = serialize_message;
const get_pubkey = function () {
    const hostId = getConfiguredHostId();
    const auth = generate_auth(hostId);
    return getSodium().to_hex(auth.publicKey);
};
exports.get_pubkey = get_pubkey;
const setup = function (options = {}) {
    const parsedOptionsResult = SetupOptionsSchema.safeParse(options);
    const parsedOptions = parsedOptionsResult.success
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
    console.log("Public key is", (0, exports.get_pubkey)());
};
exports.setup = setup;
const encrypt = function (message) {
    const hostId = getConfiguredHostId();
    const hostPublicKey = getConfiguredHostPublicKey();
    const sodium = getSodium();
    const serialized = (0, exports.serialize_message)(message);
    const auth = generate_auth(hostId);
    const nonce = sodium.randombytes_buf(sodium.crypto_box_NONCEBYTES);
    const ciphertext = sodium.crypto_box_easy(serialized, nonce, hostPublicKey, auth.privateKey);
    return {
        ciphertext: sodium.to_hex(ciphertext),
        nonce: sodium.to_hex(nonce),
    };
};
exports.encrypt = encrypt;
const decrypt = function (data) {
    const parsedDataResult = DecryptPayloadSchema.safeParse(data);
    if (!parsedDataResult.success) {
        return false;
    }
    const hostId = getConfiguredHostId();
    const hostPublicKey = getConfiguredHostPublicKey();
    const sodium = getSodium();
    const auth = generate_auth(hostId);
    try {
        const decrypted = sodium.crypto_box_open_easy(sodium.from_hex(parsedDataResult.data.ciphertext), sodium.from_hex(parsedDataResult.data.nonce), hostPublicKey, auth.privateKey);
        if (!decrypted) {
            return false;
        }
        const message = sodium.to_string(decrypted);
        try {
            return JSON.parse(message);
        }
        catch {
            return message;
        }
    }
    catch {
        return false;
    }
};
exports.decrypt = decrypt;
function fingerprint(raw = false) {
    const cpuData = {};
    const cpus = node_os_1.default.cpus();
    if (Array.isArray(cpus)) {
        cpuData.cores = cpus.length;
        cpuData.models = cpus.map((cpu) => cpu.model);
    }
    const information = {
        os: node_os_1.default.type(),
        user: node_os_1.default.userInfo(),
        architecture: node_os_1.default.arch(),
        cpu: cpuData,
        endianness: node_os_1.default.endianness(),
        hostname: node_os_1.default.hostname(),
        machine: node_os_1.default.machine(),
        network: JSON.stringify(node_os_1.default.networkInterfaces()),
        platform: node_os_1.default.platform(),
        memory: node_os_1.default.totalmem(),
    };
    if (raw) {
        return information;
    }
    const buffer = getSodium().crypto_generichash(getSodium().crypto_generichash_BYTES_MAX, JSON.stringify(information));
    return getSodium().to_hex(buffer);
}
exports.default = {
    serialize_message: exports.serialize_message,
    setup: exports.setup,
    get_pubkey: exports.get_pubkey,
    encrypt: exports.encrypt,
    decrypt: exports.decrypt,
    fingerprint,
};
//# sourceMappingURL=machine.js.map