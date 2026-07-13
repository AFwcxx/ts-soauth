import { z } from "zod";
export declare function hexString(options?: {
    exactBytes?: number;
    minBytes?: number;
    maxBytes?: number;
}): z.ZodString;
