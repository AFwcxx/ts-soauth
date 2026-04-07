"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.get_box_pubkey = exports.decrypt = exports.encrypt = exports.check_store_data = exports.SOAUTH_MACHINE_STOREDATA = exports.SOAUTH_HUMAN_STOREDATA = exports.verify_token = exports.negotiate = exports.serialize_message = exports.setup = void 0;
const libsodium_wrappers_1 = __importDefault(require("libsodium-wrappers"));
const zod_1 = require("zod");
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
const HEX_REGEX = /^[0-9a-f]+$/i;
function hexString(options) {
    let schema = zod_1.z.string().regex(HEX_REGEX, "Invalid hex format");
    if (typeof options?.exactBytes === "number") {
        schema = schema.length(options.exactBytes * 2);
    }
    if (typeof options?.maxBytes === "number") {
        schema = schema.max(options.maxBytes * 2);
    }
    return schema;
}
const NegotiationEnvelopeSchema = zod_1.z.looseObject({
    sealed: hexString({ maxBytes: 16_384 }),
    hostId: zod_1.z.string().min(1).max(255),
});
const NegotiationPayloadSchema = zod_1.z.looseObject({
    signature: hexString({ maxBytes: 16_384 }),
    signPublicKey: hexString({ exactBytes: 32 }),
});
const SignedMessageSchema = zod_1.z.looseObject({
    intention: zod_1.z.enum(SOAUTH_INTENTIONS),
    boxPublicKey: hexString({ exactBytes: 32 }),
    serverSignPublicKey: hexString({ exactBytes: 32 }),
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
    ciphertext: hexString({ maxBytes: 64_000 }),
    nonce: hexString({ exactBytes: 24 }),
    token: hexString({ exactBytes: 64 }).optional(),
});
const SOAUTH = {
    sodium: libsodium_wrappers_1.default,
    secret: false,
    serves: false,
};
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
    return SOAUTH.sodium;
}
function getSecret() {
    if (!SOAUTH.secret) {
        throw new Error("SoAuth: Invalid secret format.");
    }
    return SOAUTH.secret;
}
function getServes() {
    if (!Array.isArray(SOAUTH.serves) || SOAUTH.serves.length === 0) {
        throw new Error("SoAuth: Invalid serves format.");
    }
    return SOAUTH.serves;
}
function normalizeBoxPublicKey(boxPublicKey) {
    const sodium = getSodium();
    if (isUint8Array(boxPublicKey)) {
        return sodium.to_hex(boxPublicKey);
    }
    return boxPublicKey;
}
function generate_sign(hostId) {
    const sodium = getSodium();
    const seed = sodium.crypto_generichash(sodium.crypto_generichash_BYTES_MAX, getSecret() + hostId);
    const signSeed = sodium.crypto_generichash(sodium.crypto_box_SEEDBYTES, seed);
    return sodium.crypto_box_seed_keypair(signSeed);
}
function generate_auth(hostId, boxPublicKey) {
    const sodium = getSodium();
    const normalizedBoxPublicKey = normalizeBoxPublicKey(boxPublicKey);
    const seed = sodium.crypto_generichash(sodium.crypto_generichash_BYTES_MAX, getSecret() + hostId + normalizedBoxPublicKey);
    const boxSeed = sodium.crypto_generichash(sodium.crypto_box_SEEDBYTES, seed);
    const boxKeypair = sodium.crypto_box_seed_keypair(boxSeed);
    return {
        ...boxKeypair,
        token: sodium.crypto_generichash(sodium.crypto_generichash_BYTES_MAX, sodium.to_hex(boxKeypair.publicKey) + hostId),
    };
}
const setup = function (options = {}) {
    const sodium = getSodium();
    const optionBag = isObjectLike(options) ? options : {};
    const secretResult = SecretSchema.safeParse(optionBag.secret);
    const servesResult = ServesSchema.safeParse(optionBag.serves);
    SOAUTH.secret = secretResult.success ? secretResult.data : false;
    SOAUTH.serves = servesResult.success ? servesResult.data : false;
    if (!SOAUTH.secret) {
        throw new Error("SoAuth: Invalid secret format.");
    }
    if (!SOAUTH.serves) {
        throw new Error("SoAuth: Invalid serves format.");
    }
    for (let i = 0; i < SOAUTH.serves.length; i += 1) {
        const sign = generate_sign(SOAUTH.serves[i]);
        console.log("Signature public key for " + SOAUTH.serves[i] + " is", sodium.to_hex(sign.publicKey));
    }
};
exports.setup = setup;
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
const negotiate = function (request) {
    const response = {
        success: false,
        message: "Invalid request",
        sealed: null,
        data: null,
    };
    try {
        const sodium = getSodium();
        const negotiationEnvelope = parseBoundary(NegotiationEnvelopeSchema, request, "Invalid request format.");
        const hostId = negotiationEnvelope.hostId;
        if (!getServes().includes(hostId)) {
            throw new Error("Invalid host id.");
        }
        const sign = generate_sign(hostId);
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
        const auth = generate_auth(hostId, message.boxPublicKey);
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
    catch (error) {
        console.error("SoAuth negotiate failed:", error);
        response.message = "Invalid request";
        return response;
    }
    response.success = true;
    response.message = "OK";
    return response;
};
exports.negotiate = negotiate;
const verify_token = function (hostId, boxPublicKey, token) {
    const parsed = parseBoundary(VerifyTokenParamsSchema, { hostId, boxPublicKey, token }, "SoAuth: Invalid verify_token parameters.");
    const sodium = getSodium();
    const auth = generate_auth(parsed.hostId, parsed.boxPublicKey);
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
exports.verify_token = verify_token;
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
const encrypt = function (message, hostId, boxPublicKey) {
    const parsed = parseBoundary(StringBoxPublicKeyParamsSchema, { hostId, boxPublicKey }, "Expecting boxPublicKey to be string.");
    const sodium = getSodium();
    const peerBoxPublicKey = sodium.from_hex(parsed.boxPublicKey);
    const serialized = (0, exports.serialize_message)(message);
    const auth = generate_auth(parsed.hostId, peerBoxPublicKey);
    const nonce = sodium.randombytes_buf(sodium.crypto_box_NONCEBYTES);
    const ciphertext = sodium.crypto_box_easy(serialized, nonce, peerBoxPublicKey, auth.privateKey);
    return {
        ciphertext: sodium.to_hex(ciphertext),
        nonce: sodium.to_hex(nonce),
    };
};
exports.encrypt = encrypt;
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
    if (typeof parsedData.token === "string" &&
        !(0, exports.verify_token)(parsedKey.hostId, parsedKey.boxPublicKey, parsedData.token)) {
        return false;
    }
    const sodium = getSodium();
    const auth = generate_auth(parsedKey.hostId, parsedKey.boxPublicKey);
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
};
exports.decrypt = decrypt;
const get_box_pubkey = function (hostId, boxPublicKey) {
    const parsed = parseBoundary(GetBoxPubkeyParamsSchema, { hostId, boxPublicKey }, "SoAuth: Invalid get_box_pubkey parameters.");
    const auth = generate_auth(parsed.hostId, parsed.boxPublicKey);
    return getSodium().to_hex(auth.publicKey);
};
exports.get_box_pubkey = get_box_pubkey;
exports.default = {
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
//# sourceMappingURL=host.js.map