import { certificateAuthority } from "./default.json";
import { serverTrustRoots } from "./production.json";

export const SIGNAL_CA_PEM = certificateAuthority;

// Signal production "unidentified delivery" trust roots, as used by
// Signal-Desktop config/production.json -> serverTrustRoots. Multiple roots
// are published; any may sign a sealed-sender certificate, so we try each.
export const SIGNAL_UD_TRUST_ROOTS_B64 = serverTrustRoots;
