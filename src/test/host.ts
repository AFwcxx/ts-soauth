#!/usr/bin/env node
"use strict";

import express, {
  type ErrorRequestHandler,
  type RequestHandler,
} from "express";
import path from "path";
import http from "http";
import cors from "cors";
import fs from "fs/promises";
import sodium from "libsodium-wrappers";
import { z } from "zod";
import { Host } from "../index";

const EnvSchema = z.object({
  PORT: z.string().optional(),
  PWD: z.string().min(1),
  CORS_ORIGIN: z.url().optional(),
  NODE_ENV: z.string().optional(),
});

const FingerprintHeaderSchema = z.looseObject({
  "soauth-fingerprint": z.preprocess((value) => {
    if (Array.isArray(value)) {
      return value[0];
    }

    return value;
  }, z.string().min(1)),
});

const NegotiateBodySchema = z.looseObject({
  hostId: z.string().min(1),
  sealed: z.string().min(1),
});

const MessageBodySchema = z.looseObject({
  token: z.string().min(1),
});

const ObjectBodySchema = z.record(z.string(), z.unknown());

const PrivateQuerySchema = z.looseObject({
  soauth: z.preprocess((value) => {
    if (Array.isArray(value)) {
      return typeof value[0] === "string" ? value[0] : undefined;
    }

    return value;
  }, z.string().min(1).optional()),
});

const PrivateParamsSchema = z.looseObject({
  path: z.preprocess((value) => {
    if (Array.isArray(value)) {
      return value.join("/");
    }

    return typeof value === "string" ? value : undefined;
  }, z.string().optional()),
  soauth: z.string().min(1).optional(),
});

const SESSION_TTL_MS = 1000 * 60 * 60; // 1 hour

function isHumanSessionExpired(session: HumanDataRecord): boolean {
  return Date.now() - session.ts.getTime() > SESSION_TTL_MS;
}

function findActiveHumanSessionIndexByToken(token: string): number {
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

const MachineRegistrationSchema = z.object({
  hostId: z.string().min(1),
  fingerprint: z.string().min(1),
  publicKey: z.string().min(1),
});

type AppEnv = z.infer<typeof EnvSchema>;
type MachineDataRecord = z.infer<typeof MachineRegistrationSchema>;
type HostNegotiationResult = ReturnType<typeof Host.negotiate>;
type HostNegotiationData = NonNullable<HostNegotiationResult["data"]>;
type HumanDataRecord = HostNegotiationData & {
  fingerprint: string;
  ts: Date;
};

type NormalizedPort = number | string | false;

function normalizePort(value: string): NormalizedPort {
  const port = Number.parseInt(value, 10);

  if (Number.isNaN(port)) {
    return value;
  }

  if (port >= 0) {
    return port;
  }

  return false;
}

function getErrorMessage(error: unknown): string {
  if (error instanceof Error) {
    return error.message;
  }

  return "Unknown error";
}

const env: AppEnv = EnvSchema.parse(process.env);
const port: NormalizedPort = normalizePort(env.PORT ?? "3000");
const PRIVATE_DIR = path.resolve(env.PWD, "private");

const app = express();
app.set("port", port);
app.disable("x-powered-by");
const corsOptions = {
  origin: "http://127.0.0.1:8080", // replace with your frontend's exact origin
  methods: ["GET", "POST", "OPTIONS"],
  allowedHeaders: ["Content-Type", "soauth-fingerprint"],
};

app.use(cors(corsOptions));
app.options("/{*any}", cors(corsOptions));
app.use(express.json({ limit: "16kb" }));

const server = http.createServer(app);

server.on("error", (error: NodeJS.ErrnoException): void => {
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

server.on("listening", (): void => {
  const addr = server.address();

  if (addr == null) {
    console.log("Listening");
    return;
  }

  const bind = typeof addr === "string" ? `pipe ${addr}` : `port ${addr.port}`;
  console.log(`Listening on ${bind}`);
});

const humanData: HumanDataRecord[] = [];
const machineData: MachineDataRecord[] = [];

const registerMachine: MachineDataRecord = {
  hostId: "test-host-id",
  fingerprint: "test-machine",
  publicKey: "02a131f6c11648f43757163d71622ac524e303e2e68c0e5bad4eaec07437847c",
};

app.post("/negotiate", (req, res, next): void => {
  try {
    const parsedHeaders = FingerprintHeaderSchema.safeParse(req.headers);

    if (!parsedHeaders.success) {
      throw new Error("Expecting SoAuth fingerprint header.");
    }

    const parsedBody = NegotiateBodySchema.safeParse(req.body as unknown);

    if (!parsedBody.success) {
      throw new Error("Invalid request");
    }

    const result = Host.negotiate(parsedBody.data) as HostNegotiationResult & {
      sealed?: HostNegotiationResult["sealed"];
      data?: HostNegotiationResult["data"];
    };

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

      if (Host.check_store_data(Host.SOAUTH_HUMAN_STOREDATA, storeCandidate)) {
        const foundHumanDataIndex = humanData.findIndex((item) => {
          return (
            item.signPublicKey === resultData.signPublicKey &&
            item.hostId === resultData.hostId
          );
        });

        const storedHumanData: HumanDataRecord = {
          ...storeCandidate,
          ts: new Date(),
        };

        if (
          storedHumanData.intention === "login" &&
          foundHumanDataIndex !== -1
        ) {
          humanData[foundHumanDataIndex] = storedHumanData;
          pass = true;
        } else if (
          storedHumanData.intention === "register" &&
          foundHumanDataIndex === -1
        ) {
          humanData.push(storedHumanData);
          pass = true;
        }
      }
    }

    if (!pass) {
      result.success = false;
      result.message = `Unable to ${resultData?.intention ?? "process request"}`;
      delete (result as any).sealed;
    }

    console.log("Human Data:");
    console.dir(
      humanData.map((item) => ({
        hostId: item.hostId,
        signPublicKey: item.signPublicKey,
        fingerprint: item.fingerprint,
        intention: item.intention,
        ts: item.ts,
      })),
      { depth: null },
    );

    delete (result as any).data;

    res.json(result);
  } catch (error) {
    next(error);
  }
});

app.post("/message", (req, res, next): void => {
  try {
    const parsedBody = MessageBodySchema.safeParse(req.body as unknown);

    if (!parsedBody.success) {
      res.json({
        success: false,
        message: "Insufficient parameter received.",
      });
      return;
    }

    const foundHumanDataIndex = findActiveHumanSessionIndexByToken(
      parsedBody.data.token,
    );

    if (foundHumanDataIndex === -1) {
      res.json({
        success: false,
        message: "Invalid request.",
      });
      return;
    }

    const { hostId, boxPublicKey } = humanData[foundHumanDataIndex];
    const result = Host.decrypt(req.body as unknown, hostId, boxPublicKey);

    console.log("result", result);

    res.json(Host.encrypt(result, hostId, boxPublicKey));
  } catch (error) {
    next(error);
  }
});

app.post("/machine", (req, res, next): void => {
  try {
    const parsedHeaders = FingerprintHeaderSchema.safeParse(req.headers);

    if (!parsedHeaders.success) {
      res.json({
        success: false,
        message: "Insufficient parameter received.",
      });
      return;
    }

    const parsedBody = ObjectBodySchema.safeParse(req.body as unknown);

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
    const result = Host.decrypt(parsedBody.data, hostId, publicKey);

    console.log("result", result);

    res.json(Host.encrypt(result, hostId, publicKey));
  } catch (error) {
    next(error);
  }
});

app.all("/private/{*path}", async (req, res, next): Promise<void> => {
  const fullUrl = `${req.protocol}://${String(req.get("host"))}${req.originalUrl}`;
  console.log("Requested for:", fullUrl);

  try {
    const parsedQuery = PrivateQuerySchema.safeParse(req.query as unknown);
    const parsedParams = PrivateParamsSchema.safeParse(req.params as unknown);

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
    const filePath = path.resolve(PRIVATE_DIR, relativePath);

    if (
      filePath !== PRIVATE_DIR &&
      !filePath.startsWith(`${PRIVATE_DIR}${path.sep}`)
    ) {
      res.status(400).send("Invalid file path");
      return;
    }

    console.log("File Path:", filePath);

    const stats = await fs.stat(filePath).catch(() => null);

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
  } catch (error) {
    next(error);
  }
});

const notFoundHandler: RequestHandler = (_req, _res, next): void => {
  next(new Error("Not found"));
};

app.use(notFoundHandler);

const errorHandler: ErrorRequestHandler = (
  error,
  _req,
  res,
  _next,
): void => {
  console.error("Error", error);

  const message =
    env.NODE_ENV === "development" ? getErrorMessage(error) : "Internal server error";

  res.status(500).json({
    success: false,
    message,
  });
};

app.use(errorHandler);

async function bootstrap(): Promise<void> {
  await sodium.ready;

  Host.setup({
    secret: "secret",
    serves: ["test-host-id"],
  });

  if (Host.check_store_data(Host.SOAUTH_MACHINE_STOREDATA, registerMachine)) {
    machineData.push(registerMachine);
  }

  for (let i = 0; i < machineData.length; i += 1) {
    const boxPublicKey = Host.get_box_pubkey(
      machineData[i].hostId,
      machineData[i].publicKey,
    );

    console.log(
      `Box public key for ${machineData[i].fingerprint} is ${boxPublicKey}`,
    );
  }

  server.listen(port as number | string);
}

void bootstrap().catch((error: unknown) => {
  console.error("Bootstrap error:", error);
  process.exit(1);
});

