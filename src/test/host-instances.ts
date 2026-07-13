#!/usr/bin/env node
"use strict";

import assert from "node:assert/strict";
import sodium from "libsodium-wrappers";

import { createHost, Host } from "../index";

type ClientKeyPairs = {
  box: {
    publicKey: Uint8Array;
    privateKey: Uint8Array;
  };
  sign: {
    publicKey: Uint8Array;
    privateKey: Uint8Array;
  };
};

type NegotiationResult = {
  success: boolean;
  message: string;
  sealed: string | null;
  data: {
    intention: "register" | "login";
    hostId: string;
    boxPublicKey: string;
    signPublicKey: string;
    meta: unknown;
    token: string;
  } | null;
};

function deriveHostSignKeyPair(secret: string, hostId: string): {
  publicKey: Uint8Array;
  privateKey: Uint8Array;
} {
  const seed = sodium.crypto_generichash(
    sodium.crypto_generichash_BYTES_MAX,
    secret + hostId,
  );
  const signSeed = sodium.crypto_generichash(sodium.crypto_box_SEEDBYTES, seed);

  return sodium.crypto_box_seed_keypair(signSeed);
}

function deriveHostAuthKeyPair(
  secret: string,
  hostId: string,
  clientBoxPublicKey: Uint8Array,
): { publicKey: Uint8Array; privateKey: Uint8Array; token: Uint8Array } {
  const clientBoxPublicKeyHex = sodium.to_hex(clientBoxPublicKey);
  const seed = sodium.crypto_generichash(
    sodium.crypto_generichash_BYTES_MAX,
    secret + hostId + clientBoxPublicKeyHex,
  );
  const boxSeed = sodium.crypto_generichash(sodium.crypto_box_SEEDBYTES, seed);
  const keyPair = sodium.crypto_box_seed_keypair(boxSeed);

  return {
    ...keyPair,
    token: sodium.crypto_generichash(
      sodium.crypto_generichash_BYTES_MAX,
      sodium.to_hex(keyPair.publicKey) + hostId,
    ),
  };
}

function createClient(): ClientKeyPairs {
  return {
    box: sodium.crypto_box_keypair(),
    sign: sodium.crypto_sign_keypair(),
  };
}

function createNegotiationRequest(
  secret: string,
  hostId: string,
  client: ClientKeyPairs,
  intention: "register" | "login" = "register",
): { hostId: string; sealed: string } {
  const hostSign = deriveHostSignKeyPair(secret, hostId);
  const signedMessage = JSON.stringify({
    intention,
    meta: { test: "host-instances" },
    boxPublicKey: sodium.to_hex(client.box.publicKey),
    serverSignPublicKey: sodium.to_hex(hostSign.publicKey),
  });
  const signature = sodium.crypto_sign(
    sodium.from_string(signedMessage),
    client.sign.privateKey,
  );
  const payload = JSON.stringify({
    signature: sodium.to_hex(signature),
    signPublicKey: sodium.to_hex(client.sign.publicKey),
  });
  const sealed = sodium.crypto_box_seal(
    sodium.from_string(payload),
    hostSign.publicKey,
  );

  return { hostId, sealed: sodium.to_hex(sealed) };
}

function openNegotiationResponse(
  result: NegotiationResult,
  client: ClientKeyPairs,
): { intention: string; boxPublicKey: string; token: string } {
  assert.equal(result.success, true);
  assert.notEqual(result.sealed, null);

  const opened = sodium.crypto_box_seal_open(
    sodium.from_hex(result.sealed as string),
    client.box.publicKey,
    client.box.privateKey,
  );

  assert.ok(opened);
  return JSON.parse(sodium.to_string(opened)) as {
    intention: string;
    boxPublicKey: string;
    token: string;
  };
}

function createClientEnvelope(
  secret: string,
  hostId: string,
  client: ClientKeyPairs,
  message: unknown,
): { ciphertext: string; nonce: string; token: string } {
  const auth = deriveHostAuthKeyPair(secret, hostId, client.box.publicKey);
  const nonce = sodium.randombytes_buf(sodium.crypto_box_NONCEBYTES);
  const ciphertext = sodium.crypto_box_easy(
    sodium.from_string(JSON.stringify(message)),
    nonce,
    auth.publicKey,
    client.box.privateKey,
  );

  return {
    ciphertext: sodium.to_hex(ciphertext),
    nonce: sodium.to_hex(nonce),
    token: sodium.to_hex(auth.token),
  };
}

async function main(): Promise<void> {
  await sodium.ready;

  const hostId = "shared-host-id";
  const alphaSecret = "host-instances-alpha-secret";
  const betaSecret = "host-instances-beta-secret";
  const alpha = createHost({ secret: alphaSecret, serves: [hostId, "alpha-only"] });
  const beta = createHost({ secret: betaSecret, serves: [hostId, "beta-only"] });
  const client = createClient();
  const clientBoxPublicKey = sodium.to_hex(client.box.publicKey);

  // An instance copies its served IDs rather than retaining caller-owned state.
  const mutableServes = ["copied-host-id"];
  const copiedConfigurationHost = createHost({
    secret: alphaSecret,
    serves: mutableServes,
  });
  mutableServes[0] = "mutated-host-id";
  assert.doesNotThrow(() =>
    copiedConfigurationHost.get_box_pubkey("copied-host-id", clientBoxPublicKey),
  );
  assert.throws(() =>
    copiedConfigurationHost.get_box_pubkey("mutated-host-id", clientBoxPublicKey),
  );

  // Same host ID with different secrets must generate unrelated host auth keys.
  const alphaBoxPublicKey = alpha.get_box_pubkey(hostId, clientBoxPublicKey);
  const betaBoxPublicKey = beta.get_box_pubkey(hostId, clientBoxPublicKey);
  assert.notEqual(alphaBoxPublicKey, betaBoxPublicKey);
  assert.throws(() => alpha.get_box_pubkey("beta-only", clientBoxPublicKey));
  assert.throws(() => beta.get_box_pubkey("alpha-only", clientBoxPublicKey));

  // Negotiation accepts only the instance that owns the matching derived key.
  const alphaRequest = createNegotiationRequest(alphaSecret, hostId, client);
  const alphaNegotiation = alpha.negotiate(alphaRequest) as NegotiationResult;
  const openedAlpha = openNegotiationResponse(alphaNegotiation, client);
  assert.equal(openedAlpha.boxPublicKey, alphaBoxPublicKey);
  assert.equal(alphaNegotiation.data?.token, openedAlpha.token);

  const rejectedByBeta = beta.negotiate(alphaRequest) as NegotiationResult;
  assert.equal(rejectedByBeta.success, false);
  assert.equal(rejectedByBeta.message, "Invalid request");
  assert.equal(rejectedByBeta.sealed, null);
  assert.equal(rejectedByBeta.data, null);
  assert.equal(rejectedByBeta.message.includes(alphaSecret), false);
  assert.equal(rejectedByBeta.message.includes(betaSecret), false);

  // Tokens are bound to the Host instance even when the served host ID is shared.
  const alphaToken = alphaNegotiation.data?.token as string;
  assert.equal(alpha.verify_token(hostId, clientBoxPublicKey, alphaToken), true);
  assert.equal(beta.verify_token(hostId, clientBoxPublicKey, alphaToken), false);

  const betaRequest = createNegotiationRequest(betaSecret, hostId, client, "login");
  const betaNegotiation = beta.negotiate(betaRequest) as NegotiationResult;
  const openedBeta = openNegotiationResponse(betaNegotiation, client);
  const betaToken = betaNegotiation.data?.token as string;
  assert.equal(openedBeta.boxPublicKey, betaBoxPublicKey);
  assert.notEqual(alphaToken, betaToken);
  assert.equal(beta.verify_token(hostId, clientBoxPublicKey, betaToken), true);
  assert.equal(alpha.verify_token(hostId, clientBoxPublicKey, betaToken), false);

  // A client envelope authenticated to one Host cannot be decrypted by another.
  const alphaEnvelope = createClientEnvelope(alphaSecret, hostId, client, {
    owner: "alpha",
  });
  assert.deepEqual(alpha.decrypt(alphaEnvelope, hostId, clientBoxPublicKey), {
    owner: "alpha",
  });
  assert.equal(beta.decrypt(alphaEnvelope, hostId, clientBoxPublicKey), false);

  // Host-to-client ciphertext is likewise specific to the originating Host.
  const encryptedByAlpha = alpha.encrypt(
    { owner: "alpha" },
    hostId,
    clientBoxPublicKey,
  );
  const openedByClient = sodium.crypto_box_open_easy(
    sodium.from_hex(encryptedByAlpha.ciphertext),
    sodium.from_hex(encryptedByAlpha.nonce),
    sodium.from_hex(alphaBoxPublicKey),
    client.box.privateKey,
  );
  assert.ok(openedByClient);
  assert.deepEqual(JSON.parse(sodium.to_string(openedByClient)), {
    owner: "alpha",
  });
  assert.throws(
    () =>
      sodium.crypto_box_open_easy(
        sodium.from_hex(encryptedByAlpha.ciphertext),
        sodium.from_hex(encryptedByAlpha.nonce),
        sodium.from_hex(betaBoxPublicKey),
        client.box.privateKey,
      ),
  );

  // Interleaved work must retain instance configuration without state overwrite.
  const concurrent = await Promise.all(
    Array.from({ length: 24 }, async (_, index) => {
      await Promise.resolve();

      const target = index % 2 === 0 ? alpha : beta;
      const secret = index % 2 === 0 ? alphaSecret : betaSecret;
      const concurrentClient = createClient();
      const request = createNegotiationRequest(secret, hostId, concurrentClient);
      const result = target.negotiate(request) as NegotiationResult;
      const response = openNegotiationResponse(result, concurrentClient);
      const publicKey = sodium.to_hex(concurrentClient.box.publicKey);

      return {
        target,
        publicKey,
        token: response.token,
        owned: target.verify_token(hostId, publicKey, response.token),
        otherOwns: (target === alpha ? beta : alpha).verify_token(
          hostId,
          publicKey,
          response.token,
        ),
      };
    }),
  );

  for (const result of concurrent) {
    assert.equal(result.owned, true);
    assert.equal(result.otherOwns, false);
  }

  // The legacy singleton facade retains its API and is isolated from instances.
  Host.setup({ secret: alphaSecret, serves: [hostId] });
  assert.equal(Host.get_box_pubkey(hostId, clientBoxPublicKey), alphaBoxPublicKey);
  assert.equal(Host.verify_token(hostId, clientBoxPublicKey, alphaToken), true);
  assert.equal(Host.verify_token(hostId, clientBoxPublicKey, betaToken), false);
  const legacyNegotiation = Host.negotiate(alphaRequest) as NegotiationResult;
  assert.deepEqual(openNegotiationResponse(legacyNegotiation, client), openedAlpha);
  assert.deepEqual(Host.decrypt(alphaEnvelope, hostId, clientBoxPublicKey), {
    owner: "alpha",
  });
  const encryptedByLegacyHost = Host.encrypt(
    { owner: "legacy-alpha" },
    hostId,
    clientBoxPublicKey,
  );
  const openedByClientFromLegacyHost = sodium.crypto_box_open_easy(
    sodium.from_hex(encryptedByLegacyHost.ciphertext),
    sodium.from_hex(encryptedByLegacyHost.nonce),
    sodium.from_hex(alphaBoxPublicKey),
    client.box.privateKey,
  );
  assert.ok(openedByClientFromLegacyHost);
  assert.deepEqual(JSON.parse(sodium.to_string(openedByClientFromLegacyHost)), {
    owner: "legacy-alpha",
  });
  assert.equal(beta.verify_token(hostId, clientBoxPublicKey, betaToken), true);

  Host.setup({ secret: betaSecret, serves: [hostId] });
  assert.equal(Host.verify_token(hostId, clientBoxPublicKey, alphaToken), false);
  assert.equal(Host.verify_token(hostId, clientBoxPublicKey, betaToken), true);
  assert.equal(alpha.verify_token(hostId, clientBoxPublicKey, alphaToken), true);

  // A rejected legacy reconfiguration must fail closed, not retain old keys.
  assert.throws(() => Host.setup({ secret: "", serves: [hostId] }));
  assert.throws(() =>
    Host.verify_token(hostId, clientBoxPublicKey, betaToken),
  );
  assert.equal(beta.verify_token(hostId, clientBoxPublicKey, betaToken), true);

  console.log("Host instance isolation tests passed");
}

void main().catch((error: unknown) => {
  console.error(error);
  process.exitCode = 1;
});
