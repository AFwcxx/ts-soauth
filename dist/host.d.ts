declare const SOAUTH_INTENTIONS: readonly ["register", "login"];
type SoauthIntention = (typeof SOAUTH_INTENTIONS)[number];
type NegotiateData = {
    intention: SoauthIntention;
    hostId: string;
    boxPublicKey: string;
    signPublicKey: string;
    meta: unknown;
    token: string;
};
type NegotiateResponse = {
    success: boolean;
    message: string;
    sealed: string | null;
    data: NegotiateData | null;
};
type EncryptResult = {
    ciphertext: string;
    nonce: string;
};
export declare const setup: (options?: unknown) => void;
export declare const serialize_message: (message: unknown) => string;
export declare const negotiate: (request: unknown) => NegotiateResponse;
export declare const verify_token: (hostId: unknown, boxPublicKey: unknown, token: unknown) => boolean;
export declare const SOAUTH_HUMAN_STOREDATA: {
    readonly hostId: {
        readonly type: "string";
        readonly index: true;
    };
    readonly signPublicKey: {
        readonly type: "string";
        readonly index: true;
    };
    readonly boxPublicKey: {
        readonly type: "string";
        readonly index: false;
    };
    readonly meta: {
        readonly type: "object";
        readonly index: false;
    };
    readonly token: {
        readonly type: "string";
        readonly index: false;
    };
    readonly fingerprint: {
        readonly type: "string";
        readonly index: false;
    };
};
export declare const SOAUTH_MACHINE_STOREDATA: {
    readonly hostId: {
        readonly type: "string";
        readonly index: true;
    };
    readonly fingerprint: {
        readonly type: "string";
        readonly index: true;
    };
    readonly publicKey: {
        readonly type: "string";
        readonly index: false;
    };
};
export declare const check_store_data: (SOAUTH_STOREDATA: unknown, data: unknown) => boolean;
export declare const encrypt: (message: unknown, hostId: unknown, boxPublicKey: unknown) => EncryptResult;
export declare const decrypt: (data: unknown, hostId: unknown, boxPublicKey: unknown) => unknown | false;
export declare const get_box_pubkey: (hostId: unknown, boxPublicKey: unknown) => string;
declare const _default: {
    setup: (options?: unknown) => void;
    serialize_message: (message: unknown) => string;
    negotiate: (request: unknown) => NegotiateResponse;
    verify_token: (hostId: unknown, boxPublicKey: unknown, token: unknown) => boolean;
    SOAUTH_HUMAN_STOREDATA: {
        readonly hostId: {
            readonly type: "string";
            readonly index: true;
        };
        readonly signPublicKey: {
            readonly type: "string";
            readonly index: true;
        };
        readonly boxPublicKey: {
            readonly type: "string";
            readonly index: false;
        };
        readonly meta: {
            readonly type: "object";
            readonly index: false;
        };
        readonly token: {
            readonly type: "string";
            readonly index: false;
        };
        readonly fingerprint: {
            readonly type: "string";
            readonly index: false;
        };
    };
    SOAUTH_MACHINE_STOREDATA: {
        readonly hostId: {
            readonly type: "string";
            readonly index: true;
        };
        readonly fingerprint: {
            readonly type: "string";
            readonly index: true;
        };
        readonly publicKey: {
            readonly type: "string";
            readonly index: false;
        };
    };
    check_store_data: (SOAUTH_STOREDATA: unknown, data: unknown) => boolean;
    encrypt: (message: unknown, hostId: unknown, boxPublicKey: unknown) => EncryptResult;
    decrypt: (data: unknown, hostId: unknown, boxPublicKey: unknown) => unknown | false;
    get_box_pubkey: (hostId: unknown, boxPublicKey: unknown) => string;
};
export default _default;
