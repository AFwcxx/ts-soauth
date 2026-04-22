"use strict";

import { z } from "zod";

const HEX_REGEX = /^[0-9a-f]+$/i;

export function hexString(options?: {
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
