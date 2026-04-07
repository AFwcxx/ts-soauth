import Host from "./host";
import Machine from "./machine";
export { Host, Machine };
declare const _default: {
    Host: {
        setup: (options?: unknown) => void;
        serialize_message: (message: unknown) => string;
        negotiate: (request: unknown) => {
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
        encrypt: (message: unknown, hostId: unknown, boxPublicKey: unknown) => {
            ciphertext: string;
            nonce: string;
        };
        decrypt: (data: unknown, hostId: unknown, boxPublicKey: unknown) => unknown | false;
        get_box_pubkey: (hostId: unknown, boxPublicKey: unknown) => string;
    };
    Machine: {
        serialize_message: (message: unknown) => string;
        setup: (options?: unknown) => void;
        get_pubkey: () => string;
        encrypt: (message: unknown) => {
            ciphertext: string;
            nonce: string;
        };
        decrypt: (data: unknown) => unknown | false;
        fingerprint: typeof import("./machine").fingerprint;
    };
};
export default _default;
