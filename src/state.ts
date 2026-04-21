import { randomBytes } from "node:crypto";
import { existsSync, readFileSync, writeFileSync } from "node:fs";

import { PrivateKey } from "@signalapp/libsignal-client";

// Persisted state for the "resume" path in link.ts. Only the fields needed to
// reopen an authenticated chat connection live here — per-identity prekeys
// and sessions are owned by the file-backed stores in STORE_DIR/*.json.
// Everything below is base64-encoded when persisted.

/**
 * Next key id to allocate, per identity and per kind. Signal-Desktop keeps
 * monotonic 24-bit counters (one per ACI/PNI × preKey/signedPreKey/kyberPreKey)
 * so that freshly generated key ids never collide with ones already in the
 * store or previously uploaded to the server. See
 * `getNextKeyId` / `wrappingAdd24` in Signal-Desktop's `AccountManager`.
 */
export type KeyIdCounters = {
  preKeyIdAci: number;
  preKeyIdPni: number;
  signedPreKeyIdAci: number;
  signedPreKeyIdPni: number;
  kyberPreKeyIdAci: number;
  kyberPreKeyIdPni: number;
};

export type KeyIdKind = keyof KeyIdCounters;

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

  /** Next-key-id counters; see {@link KeyIdCounters}. */
  keyIds: KeyIdCounters;
};

export function saveState(path: string, state: LinkedState): void {
  writeFileSync(path, JSON.stringify(state, null, 2), { mode: 0o600 });
}

/**
 * Loads state from disk. For state files written before key-id counters were
 * introduced, `keyIds` will be missing; callers are expected to initialize it
 * (see `SignalClient`'s constructor) and persist again.
 */
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

// ---------- Key-id counter helpers ------------------------------------------

const KEY_ID_MASK = 0xffffff; // 24 bits

/** Wraps addition into 24 bits, matching Signal-Desktop's `wrappingAdd24`. */
export function wrappingAdd24(id: number, delta: number): number {
  return (id + delta) & KEY_ID_MASK;
}

/** Same as {@link wrappingAdd24} but never returns 0 (treated as "unset"). */
export function wrappingAdd24Nonzero(id: number, delta: number): number {
  return Math.max(1, wrappingAdd24(id, delta));
}

/** Picks a non-zero 24-bit id, used only to seed an empty counter. */
export function randomInitialKeyId(): number {
  let id = 0;
  while (id === 0) {
    id = randomBytes(3).readUIntBE(0, 3);
  }
  return id;
}

/**
 * Allocates `count` consecutive ids for `kind`, advances the counter in
 * `counters`, and returns the starting id. Callers are expected to persist
 * `counters` (usually via `saveState`) after the allocation.
 */
export function allocateKeyIds(
  counters: KeyIdCounters,
  kind: KeyIdKind,
  count: number,
): number {
  if (count < 1) throw new Error("allocateKeyIds: count must be >= 1");
  const start = counters[kind];
  counters[kind] = wrappingAdd24Nonzero(start, count);
  return start;
}

/** Allocates a single id; convenience wrapper around {@link allocateKeyIds}. */
export function allocateKeyId(
  counters: KeyIdCounters,
  kind: KeyIdKind,
): number {
  return allocateKeyIds(counters, kind, 1);
}
