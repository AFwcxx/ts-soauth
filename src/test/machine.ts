#!/usr/bin/env node
"use strict";

import http, { type IncomingMessage, type RequestOptions } from "http";
import _sodium from "libsodium-wrappers";
import { z } from "zod";

import { Machine } from "../index";

const HEX_REGEX = /^[0-9a-f]+$/i;

function hexString(options?: {
  exactBytes?: number;
  minBytes?: number;
  maxBytes?: number;
}): z.ZodString {
  let schema = z
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

const MachineResponseSchema = z.object({
  ciphertext: hexString({ minBytes: 1 }),
  nonce: hexString({ exactBytes: 24 }),
});

type MachineResponse = z.infer<typeof MachineResponseSchema>;

const machineSetupOptions = {
  secret: "secret",
  hostId: "test-host-id",
  hostPublicKey:
    "c6133c4ccba8a0643af197334ca01597879363d6371f221bcba3e0a970958a6e",
} as const;

const requestFingerprint = "test-machine";

function getErrorMessage(error: unknown): string {
  if (error instanceof Error) {
    return error.message;
  }

  if (typeof error === "object" && error !== null && "message" in error) {
    const message = (error as { message: unknown }).message;

    if (typeof message === "string") {
      return message;
    }
  }

  return String(error);
}

function createRequestOptions(postData: string): RequestOptions {
  return {
    hostname: "localhost",
    port: 3000,
    path: "/machine",
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "Content-Length": Buffer.byteLength(postData),
      "SoAuth-Fingerprint": requestFingerprint,
    },
  };
}

function handleResponse(res: IncomingMessage): void {
  res.setEncoding("utf8");

  let responseText = "";

  res.on("data", (chunk: string | Buffer) => {
    responseText += typeof chunk === "string" ? chunk : chunk.toString("utf8");
  });

  res.on("end", () => {
    try {
      const parsedJson: unknown = JSON.parse(responseText);
      const parsedResponse = MachineResponseSchema.safeParse(parsedJson);

      const encryptedResponse: MachineResponse | false = parsedResponse.success
        ? parsedResponse.data
        : false;

      const decrypted = encryptedResponse
        ? Machine.decrypt(encryptedResponse)
        : false;

      console.log("Server received", decrypted);
    } catch (error: unknown) {
      console.log("error", getErrorMessage(error));
    }
  });
}

async function main(): Promise<void> {
  await _sodium.ready;

  Machine.setup(machineSetupOptions);

  const encrypted = Machine.encrypt("hello-world");
  const postData = JSON.stringify(encrypted);
  const options = createRequestOptions(postData);

  console.log("");
  console.log("NOTE:");
  console.log("We are using 'test-machine' as Fingerprint for demo purpose.");
  console.log(
    "But we can generate a somewhat unique fingerprint with fingerprint().",
  );
  console.log("Fingerprint", Machine.fingerprint());
  console.log("");

  const req = http.request(options, handleResponse);

  req.on("error", (error: Error) => {
    console.error(`problem with request: ${error.message}`);
  });

  req.write(postData);
  req.end();
}

void main().catch((error: unknown) => {
  console.error("error", getErrorMessage(error));
  process.exitCode = 1;
});
