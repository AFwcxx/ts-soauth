"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.Machine = exports.Host = exports.createHost = void 0;
const host_1 = __importDefault(require("./host"));
exports.Host = host_1.default;
const machine_1 = __importDefault(require("./machine"));
exports.Machine = machine_1.default;
const host_2 = require("./host");
var host_3 = require("./host");
Object.defineProperty(exports, "createHost", { enumerable: true, get: function () { return host_3.createHost; } });
exports.default = {
    Host: host_1.default,
    Machine: machine_1.default,
    createHost: host_2.createHost,
};
//# sourceMappingURL=index.js.map