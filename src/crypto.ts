// On-disk encryption for state + protocol stores.
//
// A single 32-byte master key is stored in the OS credential store via
// `Bun.secrets` (Keychain on macOS, libsecret on Linux, Credential Manager on
// Windows). Every persisted file (state.json + store/*.json) is encrypted
// with AES-256-GCM using that key and a fresh random 96-bit nonce per write.
//
// File layout:
//   magic (7 bytes = "SIGCE1\x00") || nonce (12) || ciphertext || tag (16)

import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";

const MAGIC = Buffer.from("SIGCE1\x00", "ascii"); // 7 bytes
const NONCE_LEN = 12;
const TAG_LEN = 16;
const KEY_LEN = 32;

const SECRET_SERVICE = "@luisafk/signal-client";
const SECRET_NAME = "store-master-key";

/**
 * Returns the 32-byte master key from the OS credential store, generating
 * and persisting a fresh one on first use. Requires the Bun runtime.
 */
export async function getOrCreateMasterKey(opts?: {
  service?: string;
  name?: string;
}) {
  if (!Bun.secrets) {
    throw new Error(
      "Bun.secrets is not available; this client requires Bun >= 1.2 for encrypted storage",
    );
  }

  const service = opts?.service ?? SECRET_SERVICE;
  const name = opts?.name ?? SECRET_NAME;

  const existing = await Bun.secrets.get({ service, name });

  if (existing) {
    const buf = Buffer.from(existing, "base64");
    if (buf.length !== KEY_LEN) {
      throw new Error(
        `Master key in keychain has wrong length: got ${buf.length}, expected ${KEY_LEN}`,
      );
    }
    return new Uint8Array(buf);
  }

  const fresh = randomBytes(KEY_LEN);

  await Bun.secrets.set({
    service,
    name,
    value: fresh.toString("base64"),
  });

  return new Uint8Array(fresh);
}

/** Encrypts `plaintext` under `key`, returning the full on-disk envelope. */
export function encryptBlob(plaintext: Uint8Array, key: Uint8Array) {
  if (key.length !== KEY_LEN) {
    throw new Error(`encryptBlob: key must be ${KEY_LEN} bytes`);
  }

  const nonce = randomBytes(NONCE_LEN);
  const cipher = createCipheriv("aes-256-gcm", key, nonce);
  const ct = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();

  return Buffer.concat([MAGIC, nonce, ct, tag]);
}

/** Decrypts an envelope produced by {@link encryptBlob}. */
export function decryptBlob(buf: Uint8Array, key: Uint8Array) {
  if (key.length !== KEY_LEN) {
    throw new Error(`decryptBlob: key must be ${KEY_LEN} bytes`);
  }

  if (buf.length < MAGIC.length || !hasMagic(buf)) {
    throw new Error("decryptBlob: missing magic header");
  }

  const min = MAGIC.length + NONCE_LEN + TAG_LEN;
  if (buf.length < min) {
    throw new Error("decryptBlob: ciphertext too short");
  }

  const nonce = buf.subarray(MAGIC.length, MAGIC.length + NONCE_LEN);
  const tagStart = buf.length - TAG_LEN;
  const ct = buf.subarray(MAGIC.length + NONCE_LEN, tagStart);
  const tag = buf.subarray(tagStart);

  const decipher = createDecipheriv("aes-256-gcm", key, nonce);
  decipher.setAuthTag(tag);

  const pt = Buffer.concat([decipher.update(ct), decipher.final()]);

  return new Uint8Array(pt);
}

function hasMagic(buf: Uint8Array) {
  for (let i = 0; i < MAGIC.length; i++) {
    if (buf[i] !== MAGIC[i]) return false;
  }
  return true;
}
