#!/usr/bin/env node
"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const http_1 = __importDefault(require("http"));
const libsodium_wrappers_1 = __importDefault(require("libsodium-wrappers"));
const zod_1 = require("zod");
const index_1 = require("../index");
const HEX_REGEX = /^[0-9a-f]+$/i;
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
const MachineResponseSchema = zod_1.z.object({
    ciphertext: hexString({ minBytes: 1 }),
    nonce: hexString({ exactBytes: 24 }),
});
const machineSetupOptions = {
    secret: "secret",
    hostId: "test-host-id",
    hostPublicKey: "c6133c4ccba8a0643af197334ca01597879363d6371f221bcba3e0a970958a6e",
};
const requestFingerprint = "test-machine";
function getErrorMessage(error) {
    if (error instanceof Error) {
        return error.message;
    }
    if (typeof error === "object" && error !== null && "message" in error) {
        const message = error.message;
        if (typeof message === "string") {
            return message;
        }
    }
    return String(error);
}
function createRequestOptions(postData) {
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
function handleResponse(res) {
    res.setEncoding("utf8");
    let responseText = "";
    res.on("data", (chunk) => {
        responseText += typeof chunk === "string" ? chunk : chunk.toString("utf8");
    });
    res.on("end", () => {
        try {
            const parsedJson = JSON.parse(responseText);
            const parsedResponse = MachineResponseSchema.safeParse(parsedJson);
            const encryptedResponse = parsedResponse.success
                ? parsedResponse.data
                : false;
            const decrypted = encryptedResponse
                ? index_1.Machine.decrypt(encryptedResponse)
                : false;
            console.log("Server received", decrypted);
        }
        catch (error) {
            console.log("error", getErrorMessage(error));
        }
    });
}
async function main() {
    await libsodium_wrappers_1.default.ready;
    index_1.Machine.setup(machineSetupOptions);
    const encrypted = index_1.Machine.encrypt("hello-world");
    const postData = JSON.stringify(encrypted);
    const options = createRequestOptions(postData);
    console.log("");
    console.log("NOTE:");
    console.log("We are using 'test-machine' as Fingerprint for demo purpose.");
    console.log("But we can generate a somewhat unique fingerprint with fingerprint().");
    console.log("Fingerprint", index_1.Machine.fingerprint());
    console.log("");
    const req = http_1.default.request(options, handleResponse);
    req.on("error", (error) => {
        console.error(`problem with request: ${error.message}`);
    });
    req.write(postData);
    req.end();
}
void main().catch((error) => {
    console.error("error", getErrorMessage(error));
    process.exitCode = 1;
});
//# sourceMappingURL=machine.js.map