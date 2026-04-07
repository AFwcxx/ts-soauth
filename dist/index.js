"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.Machine = exports.Host = void 0;
const host_1 = __importDefault(require("./host"));
exports.Host = host_1.default;
const machine_1 = __importDefault(require("./machine"));
exports.Machine = machine_1.default;
exports.default = {
    Host: host_1.default,
    Machine: machine_1.default,
};
//# sourceMappingURL=index.js.map