#!/usr/bin/env node
"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const strict_1 = __importDefault(require("node:assert/strict"));
const libsodium_wrappers_1 = __importDefault(require("libsodium-wrappers"));
const index_1 = require("../index");
function deriveHostSignKeyPair(secret, hostId) {
    const seed = libsodium_wrappers_1.default.crypto_generichash(libsodium_wrappers_1.default.crypto_generichash_BYTES_MAX, secret + hostId);
    const signSeed = libsodium_wrappers_1.default.crypto_generichash(libsodium_wrappers_1.default.crypto_box_SEEDBYTES, seed);
    return libsodium_wrappers_1.default.crypto_box_seed_keypair(signSeed);
}
function deriveHostAuthKeyPair(secret, hostId, clientBoxPublicKey) {
    const clientBoxPublicKeyHex = libsodium_wrappers_1.default.to_hex(clientBoxPublicKey);
    const seed = libsodium_wrappers_1.default.crypto_generichash(libsodium_wrappers_1.default.crypto_generichash_BYTES_MAX, secret + hostId + clientBoxPublicKeyHex);
    const boxSeed = libsodium_wrappers_1.default.crypto_generichash(libsodium_wrappers_1.default.crypto_box_SEEDBYTES, seed);
    const keyPair = libsodium_wrappers_1.default.crypto_box_seed_keypair(boxSeed);
    return {
        ...keyPair,
        token: libsodium_wrappers_1.default.crypto_generichash(libsodium_wrappers_1.default.crypto_generichash_BYTES_MAX, libsodium_wrappers_1.default.to_hex(keyPair.publicKey) + hostId),
    };
}
function createClient() {
    return {
        box: libsodium_wrappers_1.default.crypto_box_keypair(),
        sign: libsodium_wrappers_1.default.crypto_sign_keypair(),
    };
}
function createNegotiationRequest(secret, hostId, client, intention = "register") {
    const hostSign = deriveHostSignKeyPair(secret, hostId);
    const signedMessage = JSON.stringify({
        intention,
        meta: { test: "host-instances" },
        boxPublicKey: libsodium_wrappers_1.default.to_hex(client.box.publicKey),
        serverSignPublicKey: libsodium_wrappers_1.default.to_hex(hostSign.publicKey),
    });
    const signature = libsodium_wrappers_1.default.crypto_sign(libsodium_wrappers_1.default.from_string(signedMessage), client.sign.privateKey);
    const payload = JSON.stringify({
        signature: libsodium_wrappers_1.default.to_hex(signature),
        signPublicKey: libsodium_wrappers_1.default.to_hex(client.sign.publicKey),
    });
    const sealed = libsodium_wrappers_1.default.crypto_box_seal(libsodium_wrappers_1.default.from_string(payload), hostSign.publicKey);
    return { hostId, sealed: libsodium_wrappers_1.default.to_hex(sealed) };
}
function openNegotiationResponse(result, client) {
    strict_1.default.equal(result.success, true);
    strict_1.default.notEqual(result.sealed, null);
    const opened = libsodium_wrappers_1.default.crypto_box_seal_open(libsodium_wrappers_1.default.from_hex(result.sealed), client.box.publicKey, client.box.privateKey);
    strict_1.default.ok(opened);
    return JSON.parse(libsodium_wrappers_1.default.to_string(opened));
}
function createClientEnvelope(secret, hostId, client, message) {
    const auth = deriveHostAuthKeyPair(secret, hostId, client.box.publicKey);
    const nonce = libsodium_wrappers_1.default.randombytes_buf(libsodium_wrappers_1.default.crypto_box_NONCEBYTES);
    const ciphertext = libsodium_wrappers_1.default.crypto_box_easy(libsodium_wrappers_1.default.from_string(JSON.stringify(message)), nonce, auth.publicKey, client.box.privateKey);
    return {
        ciphertext: libsodium_wrappers_1.default.to_hex(ciphertext),
        nonce: libsodium_wrappers_1.default.to_hex(nonce),
        token: libsodium_wrappers_1.default.to_hex(auth.token),
    };
}
async function main() {
    await libsodium_wrappers_1.default.ready;
    const hostId = "shared-host-id";
    const alphaSecret = "host-instances-alpha-secret";
    const betaSecret = "host-instances-beta-secret";
    const alpha = (0, index_1.createHost)({ secret: alphaSecret, serves: [hostId, "alpha-only"] });
    const beta = (0, index_1.createHost)({ secret: betaSecret, serves: [hostId, "beta-only"] });
    const client = createClient();
    const clientBoxPublicKey = libsodium_wrappers_1.default.to_hex(client.box.publicKey);
    const mutableServes = ["copied-host-id"];
    const copiedConfigurationHost = (0, index_1.createHost)({
        secret: alphaSecret,
        serves: mutableServes,
    });
    mutableServes[0] = "mutated-host-id";
    strict_1.default.doesNotThrow(() => copiedConfigurationHost.get_box_pubkey("copied-host-id", clientBoxPublicKey));
    strict_1.default.throws(() => copiedConfigurationHost.get_box_pubkey("mutated-host-id", clientBoxPublicKey));
    const alphaBoxPublicKey = alpha.get_box_pubkey(hostId, clientBoxPublicKey);
    const betaBoxPublicKey = beta.get_box_pubkey(hostId, clientBoxPublicKey);
    strict_1.default.notEqual(alphaBoxPublicKey, betaBoxPublicKey);
    strict_1.default.throws(() => alpha.get_box_pubkey("beta-only", clientBoxPublicKey));
    strict_1.default.throws(() => beta.get_box_pubkey("alpha-only", clientBoxPublicKey));
    const alphaRequest = createNegotiationRequest(alphaSecret, hostId, client);
    const alphaNegotiation = alpha.negotiate(alphaRequest);
    const openedAlpha = openNegotiationResponse(alphaNegotiation, client);
    strict_1.default.equal(openedAlpha.boxPublicKey, alphaBoxPublicKey);
    strict_1.default.equal(alphaNegotiation.data?.token, openedAlpha.token);
    const rejectedByBeta = beta.negotiate(alphaRequest);
    strict_1.default.equal(rejectedByBeta.success, false);
    strict_1.default.equal(rejectedByBeta.message, "Invalid request");
    strict_1.default.equal(rejectedByBeta.sealed, null);
    strict_1.default.equal(rejectedByBeta.data, null);
    strict_1.default.equal(rejectedByBeta.message.includes(alphaSecret), false);
    strict_1.default.equal(rejectedByBeta.message.includes(betaSecret), false);
    const alphaToken = alphaNegotiation.data?.token;
    strict_1.default.equal(alpha.verify_token(hostId, clientBoxPublicKey, alphaToken), true);
    strict_1.default.equal(beta.verify_token(hostId, clientBoxPublicKey, alphaToken), false);
    const betaRequest = createNegotiationRequest(betaSecret, hostId, client, "login");
    const betaNegotiation = beta.negotiate(betaRequest);
    const openedBeta = openNegotiationResponse(betaNegotiation, client);
    const betaToken = betaNegotiation.data?.token;
    strict_1.default.equal(openedBeta.boxPublicKey, betaBoxPublicKey);
    strict_1.default.notEqual(alphaToken, betaToken);
    strict_1.default.equal(beta.verify_token(hostId, clientBoxPublicKey, betaToken), true);
    strict_1.default.equal(alpha.verify_token(hostId, clientBoxPublicKey, betaToken), false);
    const alphaEnvelope = createClientEnvelope(alphaSecret, hostId, client, {
        owner: "alpha",
    });
    strict_1.default.deepEqual(alpha.decrypt(alphaEnvelope, hostId, clientBoxPublicKey), {
        owner: "alpha",
    });
    strict_1.default.equal(beta.decrypt(alphaEnvelope, hostId, clientBoxPublicKey), false);
    const encryptedByAlpha = alpha.encrypt({ owner: "alpha" }, hostId, clientBoxPublicKey);
    const openedByClient = libsodium_wrappers_1.default.crypto_box_open_easy(libsodium_wrappers_1.default.from_hex(encryptedByAlpha.ciphertext), libsodium_wrappers_1.default.from_hex(encryptedByAlpha.nonce), libsodium_wrappers_1.default.from_hex(alphaBoxPublicKey), client.box.privateKey);
    strict_1.default.ok(openedByClient);
    strict_1.default.deepEqual(JSON.parse(libsodium_wrappers_1.default.to_string(openedByClient)), {
        owner: "alpha",
    });
    strict_1.default.throws(() => libsodium_wrappers_1.default.crypto_box_open_easy(libsodium_wrappers_1.default.from_hex(encryptedByAlpha.ciphertext), libsodium_wrappers_1.default.from_hex(encryptedByAlpha.nonce), libsodium_wrappers_1.default.from_hex(betaBoxPublicKey), client.box.privateKey));
    const concurrent = await Promise.all(Array.from({ length: 24 }, async (_, index) => {
        await Promise.resolve();
        const target = index % 2 === 0 ? alpha : beta;
        const secret = index % 2 === 0 ? alphaSecret : betaSecret;
        const concurrentClient = createClient();
        const request = createNegotiationRequest(secret, hostId, concurrentClient);
        const result = target.negotiate(request);
        const response = openNegotiationResponse(result, concurrentClient);
        const publicKey = libsodium_wrappers_1.default.to_hex(concurrentClient.box.publicKey);
        return {
            target,
            publicKey,
            token: response.token,
            owned: target.verify_token(hostId, publicKey, response.token),
            otherOwns: (target === alpha ? beta : alpha).verify_token(hostId, publicKey, response.token),
        };
    }));
    for (const result of concurrent) {
        strict_1.default.equal(result.owned, true);
        strict_1.default.equal(result.otherOwns, false);
    }
    index_1.Host.setup({ secret: alphaSecret, serves: [hostId] });
    strict_1.default.equal(index_1.Host.get_box_pubkey(hostId, clientBoxPublicKey), alphaBoxPublicKey);
    strict_1.default.equal(index_1.Host.verify_token(hostId, clientBoxPublicKey, alphaToken), true);
    strict_1.default.equal(index_1.Host.verify_token(hostId, clientBoxPublicKey, betaToken), false);
    const legacyNegotiation = index_1.Host.negotiate(alphaRequest);
    strict_1.default.deepEqual(openNegotiationResponse(legacyNegotiation, client), openedAlpha);
    strict_1.default.deepEqual(index_1.Host.decrypt(alphaEnvelope, hostId, clientBoxPublicKey), {
        owner: "alpha",
    });
    const encryptedByLegacyHost = index_1.Host.encrypt({ owner: "legacy-alpha" }, hostId, clientBoxPublicKey);
    const openedByClientFromLegacyHost = libsodium_wrappers_1.default.crypto_box_open_easy(libsodium_wrappers_1.default.from_hex(encryptedByLegacyHost.ciphertext), libsodium_wrappers_1.default.from_hex(encryptedByLegacyHost.nonce), libsodium_wrappers_1.default.from_hex(alphaBoxPublicKey), client.box.privateKey);
    strict_1.default.ok(openedByClientFromLegacyHost);
    strict_1.default.deepEqual(JSON.parse(libsodium_wrappers_1.default.to_string(openedByClientFromLegacyHost)), {
        owner: "legacy-alpha",
    });
    strict_1.default.equal(beta.verify_token(hostId, clientBoxPublicKey, betaToken), true);
    index_1.Host.setup({ secret: betaSecret, serves: [hostId] });
    strict_1.default.equal(index_1.Host.verify_token(hostId, clientBoxPublicKey, alphaToken), false);
    strict_1.default.equal(index_1.Host.verify_token(hostId, clientBoxPublicKey, betaToken), true);
    strict_1.default.equal(alpha.verify_token(hostId, clientBoxPublicKey, alphaToken), true);
    strict_1.default.throws(() => index_1.Host.setup({ secret: "", serves: [hostId] }));
    strict_1.default.throws(() => index_1.Host.verify_token(hostId, clientBoxPublicKey, betaToken));
    strict_1.default.equal(beta.verify_token(hostId, clientBoxPublicKey, betaToken), true);
    console.log("Host instance isolation tests passed");
}
void main().catch((error) => {
    console.error(error);
    process.exitCode = 1;
});
//# sourceMappingURL=host-instances.js.map