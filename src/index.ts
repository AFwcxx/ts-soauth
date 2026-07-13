import Host from "./host";
import Machine from "./machine";
import { createHost } from "./host";

export { createHost } from "./host";
export type {
  HostInstance,
  HostOptions,
  NegotiateData,
  NegotiateResponse,
} from "./host";

export { Host, Machine };

export default {
  Host,
  Machine,
  createHost,
};
