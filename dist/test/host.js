#!/usr/bin/env node
"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const express_1 = __importDefault(require("express"));
const path_1 = __importDefault(require("path"));
const http_1 = __importDefault(require("http"));
const cors_1 = __importDefault(require("cors"));
const promises_1 = __importDefault(require("fs/promises"));
const libsodium_wrappers_1 = __importDefault(require("libsodium-wrappers"));
const zod_1 = require("zod");
const index_1 = require("../index");
const EnvSchema = zod_1.z.object({
    PORT: zod_1.z.string().optional(),
    PWD: zod_1.z.string().min(1),
    CORS_ORIGIN: zod_1.z.url().optional(),
    NODE_ENV: zod_1.z.string().optional(),
});
const FingerprintHeaderSchema = zod_1.z.looseObject({
    "soauth-fingerprint": zod_1.z.preprocess((value) => {
        if (Array.isArray(value)) {
            return value[0];
        }
        return value;
    }, zod_1.z.string().min(1)),
});
const NegotiateBodySchema = zod_1.z.looseObject({
    hostId: zod_1.z.string().min(1),
    sealed: zod_1.z.string().min(1),
});
const MessageBodySchema = zod_1.z.looseObject({
    token: zod_1.z.string().min(1),
});
const ObjectBodySchema = zod_1.z.record(zod_1.z.string(), zod_1.z.unknown());
const PrivateQuerySchema = zod_1.z.looseObject({
    soauth: zod_1.z.preprocess((value) => {
        if (Array.isArray(value)) {
            return typeof value[0] === "string" ? value[0] : undefined;
        }
        return value;
    }, zod_1.z.string().min(1).optional()),
});
const PrivateParamsSchema = zod_1.z.looseObject({
    path: zod_1.z.preprocess((value) => {
        if (Array.isArray(value)) {
            return value.join("/");
        }
        return typeof value === "string" ? value : undefined;
    }, zod_1.z.string().optional()),
    soauth: zod_1.z.string().min(1).optional(),
});
const SESSION_TTL_MS = 1000 * 60 * 60;
function isHumanSessionExpired(session) {
    return Date.now() - session.ts.getTime() > SESSION_TTL_MS;
}
function findActiveHumanSessionIndexByToken(token) {
    const index = humanData.findIndex((item) => item.token === token);
    if (index === -1) {
        return -1;
    }
    if (isHumanSessionExpired(humanData[index])) {
        humanData.splice(index, 1);
        return -1;
    }
    return index;
}
const MachineRegistrationSchema = zod_1.z.object({
    hostId: zod_1.z.string().min(1),
    fingerprint: zod_1.z.string().min(1),
    publicKey: zod_1.z.string().min(1),
});
function normalizePort(value) {
    const port = Number.parseInt(value, 10);
    if (Number.isNaN(port)) {
        return value;
    }
    if (port >= 0) {
        return port;
    }
    return false;
}
function getErrorMessage(error) {
    if (error instanceof Error) {
        return error.message;
    }
    return "Unknown error";
}
const env = EnvSchema.parse(process.env);
const port = normalizePort(env.PORT ?? "3000");
const PRIVATE_DIR = path_1.default.resolve(env.PWD, "private");
const app = (0, express_1.default)();
app.set("port", port);
app.disable("x-powered-by");
const corsOptions = {
    origin: "http://127.0.0.1:8080",
    methods: ["GET", "POST", "OPTIONS"],
    allowedHeaders: ["Content-Type", "soauth-fingerprint"],
};
app.use((0, cors_1.default)(corsOptions));
app.options("/{*any}", (0, cors_1.default)(corsOptions));
app.use(express_1.default.json({ limit: "16kb" }));
const server = http_1.default.createServer(app);
server.on("error", (error) => {
    if (error.syscall !== "listen") {
        throw error;
    }
    const bind = typeof port === "string" ? `Pipe ${port}` : `Port ${port}`;
    switch (error.code) {
        case "EACCES":
            console.error(`${bind} requires elevated privileges`);
            process.exit(1);
        case "EADDRINUSE":
            console.error(`${bind} is already in use`);
            process.exit(1);
        default:
            throw error;
    }
});
server.on("listening", () => {
    const addr = server.address();
    if (addr == null) {
        console.log("Listening");
        return;
    }
    const bind = typeof addr === "string" ? `pipe ${addr}` : `port ${addr.port}`;
    console.log(`Listening on ${bind}`);
});
const humanData = [];
const machineData = [];
const registerMachine = {
    hostId: "test-host-id",
    fingerprint: "test-machine",
    publicKey: "02a131f6c11648f43757163d71622ac524e303e2e68c0e5bad4eaec07437847c",
};
app.post("/negotiate", (req, res, next) => {
    try {
        const parsedHeaders = FingerprintHeaderSchema.safeParse(req.headers);
        if (!parsedHeaders.success) {
            throw new Error("Expecting SoAuth fingerprint header.");
        }
        const parsedBody = NegotiateBodySchema.safeParse(req.body);
        if (!parsedBody.success) {
            throw new Error("Invalid request");
        }
        const result = index_1.Host.negotiate(parsedBody.data);
        if (!result.success) {
            throw new Error(result.message);
        }
        let pass = false;
        const resultData = result.data;
        if (resultData != null && typeof resultData === "object") {
            const storeCandidate = {
                ...resultData,
                fingerprint: parsedHeaders.data["soauth-fingerprint"],
            };
            if (index_1.Host.check_store_data(index_1.Host.SOAUTH_HUMAN_STOREDATA, storeCandidate)) {
                const foundHumanDataIndex = humanData.findIndex((item) => {
                    return (item.signPublicKey === resultData.signPublicKey &&
                        item.hostId === resultData.hostId);
                });
                const storedHumanData = {
                    ...storeCandidate,
                    ts: new Date(),
                };
                if (storedHumanData.intention === "login" &&
                    foundHumanDataIndex !== -1) {
                    humanData[foundHumanDataIndex] = storedHumanData;
                    pass = true;
                }
                else if (storedHumanData.intention === "register" &&
                    foundHumanDataIndex === -1) {
                    humanData.push(storedHumanData);
                    pass = true;
                }
            }
        }
        if (!pass) {
            result.success = false;
            result.message = `Unable to ${resultData?.intention ?? "process request"}`;
            delete result.sealed;
        }
        console.log("Human Data:");
        console.dir(humanData.map((item) => ({
            hostId: item.hostId,
            signPublicKey: item.signPublicKey,
            fingerprint: item.fingerprint,
            intention: item.intention,
            ts: item.ts,
        })), { depth: null });
        delete result.data;
        res.json(result);
    }
    catch (error) {
        next(error);
    }
});
app.post("/message", (req, res, next) => {
    try {
        const parsedBody = MessageBodySchema.safeParse(req.body);
        if (!parsedBody.success) {
            res.json({
                success: false,
                message: "Insufficient parameter received.",
            });
            return;
        }
        const foundHumanDataIndex = findActiveHumanSessionIndexByToken(parsedBody.data.token);
        if (foundHumanDataIndex === -1) {
            res.json({
                success: false,
                message: "Invalid request.",
            });
            return;
        }
        const { hostId, boxPublicKey } = humanData[foundHumanDataIndex];
        const result = index_1.Host.decrypt(req.body, hostId, boxPublicKey);
        console.log("result", result);
        res.json(index_1.Host.encrypt(result, hostId, boxPublicKey));
    }
    catch (error) {
        next(error);
    }
});
app.post("/machine", (req, res, next) => {
    try {
        const parsedHeaders = FingerprintHeaderSchema.safeParse(req.headers);
        if (!parsedHeaders.success) {
            res.json({
                success: false,
                message: "Insufficient parameter received.",
            });
            return;
        }
        const parsedBody = ObjectBodySchema.safeParse(req.body);
        if (!parsedBody.success) {
            next(new Error("Invalid request."));
            return;
        }
        const fingerprint = parsedHeaders.data["soauth-fingerprint"];
        const foundMachineDataIndex = machineData.findIndex((item) => {
            return item.fingerprint === fingerprint;
        });
        if (foundMachineDataIndex === -1) {
            res.json({
                success: false,
                message: "Invalid request.",
            });
            return;
        }
        const { hostId, publicKey } = machineData[foundMachineDataIndex];
        const result = index_1.Host.decrypt(parsedBody.data, hostId, publicKey);
        console.log("result", result);
        res.json(index_1.Host.encrypt(result, hostId, publicKey));
    }
    catch (error) {
        next(error);
    }
});
app.all("/private/{*path}", async (req, res, next) => {
    const fullUrl = `${req.protocol}://${String(req.get("host"))}${req.originalUrl}`;
    console.log("Requested for:", fullUrl);
    try {
        const parsedQuery = PrivateQuerySchema.safeParse(req.query);
        const parsedParams = PrivateParamsSchema.safeParse(req.params);
        if (!parsedQuery.success || !parsedParams.success) {
            next(new Error("Invalid access."));
            return;
        }
        const token = parsedQuery.data.soauth ?? parsedParams.data.soauth;
        if (!token) {
            next(new Error("Invalid access."));
            return;
        }
        const foundHumanDataIndex = findActiveHumanSessionIndexByToken(token);
        if (foundHumanDataIndex === -1) {
            throw new Error("Invalid token.");
        }
        const relativePath = parsedParams.data.path ?? "";
        const filePath = path_1.default.resolve(PRIVATE_DIR, relativePath);
        if (filePath !== PRIVATE_DIR &&
            !filePath.startsWith(`${PRIVATE_DIR}${path_1.default.sep}`)) {
            res.status(400).send("Invalid file path");
            return;
        }
        console.log("File Path:", filePath);
        const stats = await promises_1.default.stat(filePath).catch(() => null);
        if (!stats || !stats.isFile()) {
            res.status(404).send("File not found");
            return;
        }
        res.sendFile(filePath, (error) => {
            if (error) {
                console.error("Error sending file:", error);
                res.status(500).send("Server error");
            }
        });
    }
    catch (error) {
        next(error);
    }
});
const notFoundHandler = (_req, _res, next) => {
    next(new Error("Not found"));
};
app.use(notFoundHandler);
const errorHandler = (error, _req, res, _next) => {
    console.error("Error", error);
    const message = env.NODE_ENV === "development" ? getErrorMessage(error) : "Internal server error";
    res.status(500).json({
        success: false,
        message,
    });
};
app.use(errorHandler);
async function bootstrap() {
    await libsodium_wrappers_1.default.ready;
    index_1.Host.setup({
        secret: "secret",
        serves: ["test-host-id"],
    });
    if (index_1.Host.check_store_data(index_1.Host.SOAUTH_MACHINE_STOREDATA, registerMachine)) {
        machineData.push(registerMachine);
    }
    for (let i = 0; i < machineData.length; i += 1) {
        const boxPublicKey = index_1.Host.get_box_pubkey(machineData[i].hostId, machineData[i].publicKey);
        console.log(`Box public key for ${machineData[i].fingerprint} is ${boxPublicKey}`);
    }
    server.listen(port);
}
void bootstrap().catch((error) => {
    console.error("Bootstrap error:", error);
    process.exit(1);
});
//# sourceMappingURL=host.js.map