import os from "node:os";
type EncryptResult = {
    ciphertext: string;
    nonce: string;
};
type CpuData = {
    cores?: number;
    models?: string[];
};
type FingerprintInformation = {
    os: string;
    user: ReturnType<typeof os.userInfo>;
    architecture: string;
    cpu: CpuData;
    endianness: ReturnType<typeof os.endianness>;
    hostname: string;
    machine: string;
    network: string;
    platform: NodeJS.Platform;
    memory: number;
};
export declare const serialize_message: (message: unknown) => string;
export declare const get_pubkey: () => string;
export declare const setup: (options?: unknown) => void;
export declare const encrypt: (message: unknown) => EncryptResult;
export declare const decrypt: (data: unknown) => unknown | false;
export declare function fingerprint(raw: true): FingerprintInformation;
export declare function fingerprint(raw?: false): string;
declare const _default: {
    serialize_message: (message: unknown) => string;
    setup: (options?: unknown) => void;
    get_pubkey: () => string;
    encrypt: (message: unknown) => EncryptResult;
    decrypt: (data: unknown) => unknown | false;
    fingerprint: typeof fingerprint;
};
export default _default;
