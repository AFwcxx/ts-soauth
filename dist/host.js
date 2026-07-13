"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.get_box_pubkey = exports.decrypt = exports.encrypt = exports.verify_token = exports.negotiate = exports.setup = exports.check_store_data = exports.SOAUTH_MACHINE_STOREDATA = exports.SOAUTH_HUMAN_STOREDATA = exports.serialize_message = void 0;
exports.createHost = createHost;
const libsodium_wrappers_1 = __importDefault(require("libsodium-wrappers"));
const zod_1 = require("zod");
const soauth_1 = require("./schemas/soauth");
const sodiumReady = libsodium_wrappers_1.default.ready;
let sodiumInitialized = false;
void sodiumReady.then(() => {
    sodiumInitialized = true;
});
const SOAUTH_INTENTIONS = ["register", "login"];
const SecretSchema = zod_1.z.preprocess((value) => {
    if (!value) {
        return value;
    }
    return String(value);
}, zod_1.z.string().min(1));
const ServesSchema = zod_1.z.array(zod_1.z.string()).min(1);
const NegotiationEnvelopeSchema = zod_1.z.looseObject({
    sealed: (0, soauth_1.hexString)({ maxBytes: 16_384 }),
    hostId: zod_1.z.string().min(1).max(255),
});
const NegotiationPayloadSchema = zod_1.z.looseObject({
    signature: (0, soauth_1.hexString)({ maxBytes: 16_384 }),
    signPublicKey: (0, soauth_1.hexString)({ exactBytes: 32 }),
});
const SignedMessageSchema = zod_1.z.looseObject({
    intention: zod_1.z.enum(SOAUTH_INTENTIONS),
    boxPublicKey: (0, soauth_1.hexString)({ exactBytes: 32 }),
    serverSignPublicKey: (0, soauth_1.hexString)({ exactBytes: 32 }),
    meta: zod_1.z.unknown().optional(),
});
const StoreFieldDefinitionSchema = zod_1.z.object({
    type: zod_1.z.enum(["string", "object"]),
    index: zod_1.z.boolean(),
});
const StoreDataDefinitionSchema = zod_1.z.record(zod_1.z.string(), StoreFieldDefinitionSchema);
const StringBoxPublicKeyParamsSchema = zod_1.z.object({
    hostId: zod_1.z.string(),
    boxPublicKey: zod_1.z.string(),
});
const BoxPublicKeyInputSchema = zod_1.z.union([zod_1.z.string(), zod_1.z.instanceof(Uint8Array)]);
const VerifyTokenParamsSchema = zod_1.z.object({
    hostId: zod_1.z.string(),
    boxPublicKey: BoxPublicKeyInputSchema,
    token: zod_1.z.string(),
});
const GetBoxPubkeyParamsSchema = zod_1.z.object({
    hostId: zod_1.z.string(),
    boxPublicKey: BoxPublicKeyInputSchema,
});
const DecryptEnvelopeSchema = zod_1.z.looseObject({
    ciphertext: (0, soauth_1.hexString)({ maxBytes: 64_000 }),
    nonce: (0, soauth_1.hexString)({ exactBytes: 24 }),
    token: (0, soauth_1.hexString)({ exactBytes: 64 }),
});
function parseBoundary(schema, value, errorMessage) {
    const parsed = schema.safeParse(value);
    if (!parsed.success) {
        throw new Error(errorMessage);
    }
    return parsed.data;
}
function isUint8Array(value) {
    return value instanceof Uint8Array;
}
function isObjectLike(value) {
    return typeof value === "object" && value !== null;
}
function getSodium() {
    if (!sodiumInitialized) {
        throw new Error("SoAuth: libsodium is not ready yet.");
    }
    return libsodium_wrappers_1.default;
}
function normalizeBoxPublicKey(sodium, boxPublicKey) {
    if (isUint8Array(boxPublicKey)) {
        return sodium.to_hex(boxPublicKey);
    }
    return boxPublicKey;
}
const serialize_message = function (message) {
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
exports.serialize_message = serialize_message;
exports.SOAUTH_HUMAN_STOREDATA = {
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
};
exports.SOAUTH_MACHINE_STOREDATA = {
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
};
function matchesStoreFieldType(expectedType, value) {
    return typeof value === expectedType;
}
const check_store_data = function (SOAUTH_STOREDATA, data) {
    if (typeof data !== "object" || data === null) {
        throw new Error("SoAuth: Invalid store data format.");
    }
    const storeDataDefinition = parseBoundary(StoreDataDefinitionSchema, SOAUTH_STOREDATA, "SoAuth: Invalid SOAUTH_STOREDATA data format.");
    let pass = true;
    const dataRecord = data;
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
exports.check_store_data = check_store_data;
function initializeHost(options = {}, enforceServedHostIds = true) {
    const sodium = getSodium();
    const optionBag = isObjectLike(options) ? options : {};
    const secret = parseBoundary(SecretSchema, optionBag.secret, "SoAuth: Invalid secret format.");
    const serves = Object.freeze([
        ...parseBoundary(ServesSchema, optionBag.serves, "SoAuth: Invalid serves format."),
    ]);
    const servedHostIds = new Set(serves);
    function assertServedHostId(hostId) {
        if (!servedHostIds.has(hostId)) {
            throw new Error("SoAuth: Host id is not served.");
        }
    }
    function generateSign(hostId) {
        const seed = sodium.crypto_generichash(sodium.crypto_generichash_BYTES_MAX, secret + hostId);
        const signSeed = sodium.crypto_generichash(sodium.crypto_box_SEEDBYTES, seed);
        return sodium.crypto_box_seed_keypair(signSeed);
    }
    function generateAuth(hostId, boxPublicKey) {
        const normalizedBoxPublicKey = normalizeBoxPublicKey(sodium, boxPublicKey);
        const seed = sodium.crypto_generichash(sodium.crypto_generichash_BYTES_MAX, secret + hostId + normalizedBoxPublicKey);
        const boxSeed = sodium.crypto_generichash(sodium.crypto_box_SEEDBYTES, seed);
        const boxKeypair = sodium.crypto_box_seed_keypair(boxSeed);
        return {
            ...boxKeypair,
            token: sodium.crypto_generichash(sodium.crypto_generichash_BYTES_MAX, sodium.to_hex(boxKeypair.publicKey) + hostId),
        };
    }
    const negotiate = function (request) {
        const response = {
            success: false,
            message: "Invalid request",
            sealed: null,
            data: null,
        };
        try {
            const negotiationEnvelope = parseBoundary(NegotiationEnvelopeSchema, request, "Invalid request format.");
            const hostId = negotiationEnvelope.hostId;
            assertServedHostId(hostId);
            const sign = generateSign(hostId);
            const openedSeal = sodium.crypto_box_seal_open(sodium.from_hex(negotiationEnvelope.sealed), sign.publicKey, sign.privateKey);
            const parsedNegotiation = parseBoundary(NegotiationPayloadSchema, JSON.parse(sodium.to_string(openedSeal)), "Invalid negotiation format.");
            const signature = sodium.from_hex(parsedNegotiation.signature);
            const signPublicKey = sodium.from_hex(parsedNegotiation.signPublicKey);
            const extracted = sodium.crypto_sign_open(signature, signPublicKey);
            if (!extracted) {
                throw new Error("Invalid request signature.");
            }
            const message = parseBoundary(SignedMessageSchema, JSON.parse(sodium.to_string(extracted)), "Invalid signed message format.");
            if (message.serverSignPublicKey !== sodium.to_hex(sign.publicKey)) {
                throw new Error("Invalid host signature requested.");
            }
            const auth = generateAuth(hostId, message.boxPublicKey);
            const serialized = (0, exports.serialize_message)({
                intention: message.intention,
                boxPublicKey: sodium.to_hex(auth.publicKey),
                token: sodium.to_hex(auth.token),
            });
            const sealed = sodium.crypto_box_seal(serialized, sodium.from_hex(message.boxPublicKey));
            response.data = {
                intention: message.intention,
                hostId,
                boxPublicKey: message.boxPublicKey,
                signPublicKey: sodium.to_hex(signPublicKey),
                meta: message.meta,
                token: sodium.to_hex(auth.token),
            };
            response.sealed = sodium.to_hex(sealed);
        }
        catch {
            return response;
        }
        response.success = true;
        response.message = "OK";
        return response;
    };
    const verify_token = function (hostId, boxPublicKey, token) {
        const parsed = parseBoundary(VerifyTokenParamsSchema, { hostId, boxPublicKey, token }, "SoAuth: Invalid verify_token parameters.");
        if (enforceServedHostIds && !servedHostIds.has(parsed.hostId)) {
            return false;
        }
        const auth = generateAuth(parsed.hostId, parsed.boxPublicKey);
        let providedToken;
        try {
            providedToken = sodium.from_hex(parsed.token);
        }
        catch {
            return false;
        }
        return (auth.token.length === providedToken.length &&
            sodium.memcmp(auth.token, providedToken));
    };
    const encrypt = function (message, hostId, boxPublicKey) {
        const parsed = parseBoundary(StringBoxPublicKeyParamsSchema, { hostId, boxPublicKey }, "Expecting boxPublicKey to be string.");
        if (enforceServedHostIds) {
            assertServedHostId(parsed.hostId);
        }
        const peerBoxPublicKey = sodium.from_hex(parsed.boxPublicKey);
        const serialized = (0, exports.serialize_message)(message);
        const auth = generateAuth(parsed.hostId, peerBoxPublicKey);
        const nonce = sodium.randombytes_buf(sodium.crypto_box_NONCEBYTES);
        const ciphertext = sodium.crypto_box_easy(serialized, nonce, peerBoxPublicKey, auth.privateKey);
        return {
            ciphertext: sodium.to_hex(ciphertext),
            nonce: sodium.to_hex(nonce),
        };
    };
    const decrypt = function (data, hostId, boxPublicKey) {
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
        const parsedData = parsedDataResult.data;
        const parsedKey = parsedKeyResult.data;
        if (enforceServedHostIds && !servedHostIds.has(parsedKey.hostId)) {
            return false;
        }
        if (!verify_token(parsedKey.hostId, parsedKey.boxPublicKey, parsedData.token)) {
            return false;
        }
        try {
            const auth = generateAuth(parsedKey.hostId, parsedKey.boxPublicKey);
            const decrypted = sodium.crypto_box_open_easy(sodium.from_hex(parsedData.ciphertext), sodium.from_hex(parsedData.nonce), sodium.from_hex(parsedKey.boxPublicKey), auth.privateKey);
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
    const get_box_pubkey = function (hostId, boxPublicKey) {
        const parsed = parseBoundary(GetBoxPubkeyParamsSchema, { hostId, boxPublicKey }, "SoAuth: Invalid get_box_pubkey parameters.");
        if (enforceServedHostIds) {
            assertServedHostId(parsed.hostId);
        }
        return sodium.to_hex(generateAuth(parsed.hostId, parsed.boxPublicKey).publicKey);
    };
    const host = Object.freeze({
        serialize_message: exports.serialize_message,
        negotiate,
        verify_token,
        encrypt,
        decrypt,
        get_box_pubkey,
        check_store_data: exports.check_store_data,
        SOAUTH_HUMAN_STOREDATA: exports.SOAUTH_HUMAN_STOREDATA,
        SOAUTH_MACHINE_STOREDATA: exports.SOAUTH_MACHINE_STOREDATA,
    });
    return {
        host,
        signingPublicKeys: serves.map((hostId) => [
            hostId,
            sodium.to_hex(generateSign(hostId).publicKey),
        ]),
    };
}
function createHost(options = {}) {
    return initializeHost(options).host;
}
let legacyHost = null;
function getLegacyHost() {
    if (legacyHost === null) {
        throw new Error("SoAuth: Please run setup first.");
    }
    return legacyHost;
}
const setup = function (options = {}) {
    const initialized = initializeHost(options, false);
    legacyHost = initialized.host;
    for (const [hostId, publicKey] of initialized.signingPublicKeys) {
        console.log("Signature public key for " + hostId + " is", publicKey);
    }
};
exports.setup = setup;
const negotiate = function (request) {
    return getLegacyHost().negotiate(request);
};
exports.negotiate = negotiate;
const verify_token = function (hostId, boxPublicKey, token) {
    return getLegacyHost().verify_token(hostId, boxPublicKey, token);
};
exports.verify_token = verify_token;
const encrypt = function (message, hostId, boxPublicKey) {
    return getLegacyHost().encrypt(message, hostId, boxPublicKey);
};
exports.encrypt = encrypt;
const decrypt = function (data, hostId, boxPublicKey) {
    return getLegacyHost().decrypt(data, hostId, boxPublicKey);
};
exports.decrypt = decrypt;
const get_box_pubkey = function (hostId, boxPublicKey) {
    return getLegacyHost().get_box_pubkey(hostId, boxPublicKey);
};
exports.get_box_pubkey = get_box_pubkey;
const Host = {
    setup: exports.setup,
    serialize_message: exports.serialize_message,
    negotiate: exports.negotiate,
    verify_token: exports.verify_token,
    SOAUTH_HUMAN_STOREDATA: exports.SOAUTH_HUMAN_STOREDATA,
    SOAUTH_MACHINE_STOREDATA: exports.SOAUTH_MACHINE_STOREDATA,
    check_store_data: exports.check_store_data,
    encrypt: exports.encrypt,
    decrypt: exports.decrypt,
    get_box_pubkey: exports.get_box_pubkey,
};
exports.default = Host;
//# sourceMappingURL=host.js.map