import { PrivateKey } from "@signalapp/libsignal-client";
import { existsSync, readFileSync, writeFileSync } from "node:fs";

// Persisted state for the "resume" path in link.ts. Only the fields needed to
// reopen an authenticated chat connection live here — per-identity prekeys
// and sessions are owned by the file-backed stores in STORE_DIR/*.json.
// Everything below is base64-encoded when persisted.

export type LinkedState = {
  aci: string;
  pni: string; // tagged "PNI:<uuid>"
  number: string;
  deviceId: number;
  password: string;
  registrationId: number;
  pniRegistrationId: number;
  userAgent?: string | undefined;
  readReceipts: boolean;

  // Identity keys (32 bytes each, base64)
  aciIdentityPrivate: string;
  pniIdentityPrivate: string;

  // Account-level secrets from the ProvisionMessage
  profileKey?: string | undefined;
  masterKey?: string | undefined;
  accountEntropyPool?: string | undefined;
  ephemeralBackupKey?: string | undefined;
  mediaRootBackupKey?: string | undefined;
};

export function saveState(path: string, state: LinkedState): void {
  writeFileSync(path, JSON.stringify(state, null, 2), { mode: 0o600 });
}

export function loadState(path: string): LinkedState | undefined {
  if (!existsSync(path)) return undefined;
  return JSON.parse(readFileSync(path, "utf8")) as LinkedState;
}

export function b64(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("base64");
}

export function b64d(s: string): Uint8Array<ArrayBuffer> {
  // Copy into a fresh ArrayBuffer-backed Uint8Array so callers that require
  // `Uint8Array<ArrayBuffer>` (libsignal native bindings) type-check cleanly.
  const buf = Buffer.from(s, "base64");
  const out = new Uint8Array(buf.byteLength);
  out.set(buf);
  return out;
}

export function loadPrivateKey(s: string): PrivateKey {
  return PrivateKey.deserialize(b64d(s));
}
