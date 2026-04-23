import { createCipheriv, createHmac } from "node:crypto";

import { PrivateKey, PublicKey } from "@signalapp/libsignal-client";

import { DeviceName } from "./protos.ts";

function hmac(key: Uint8Array, data: Uint8Array) {
  return createHmac("sha256", Buffer.from(key))
    .update(Buffer.from(data))
    .digest();
}

function aesCtrZero(key: Uint8Array, plaintext: Uint8Array) {
  const iv = Buffer.alloc(16); // zero counter, matches Signal-Desktop
  const c = createCipheriv("aes-256-ctr", Buffer.from(key), iv);
  return Buffer.concat([c.update(Buffer.from(plaintext)), c.final()]);
}

/**
 * Port of Signal-Desktop's encryptDeviceName -> DeviceName proto (base64).
 * Returned string is ready to place in accountAttributes.name.
 */
export function encryptDeviceName(
  deviceName: string,
  identityPublic: PublicKey,
) {
  const plaintext = Buffer.from(deviceName, "utf8");

  const ephemeralPriv = PrivateKey.generate();
  const ephemeralPub = ephemeralPriv.getPublicKey();
  const masterSecret = ephemeralPriv.agree(identityPublic);

  const key1 = hmac(masterSecret, Buffer.from("auth", "utf8"));
  const syntheticIv = hmac(key1, plaintext).subarray(0, 16);

  const key2 = hmac(masterSecret, Buffer.from("cipher", "utf8"));
  const cipherKey = hmac(key2, syntheticIv);

  const ciphertext = aesCtrZero(cipherKey, plaintext);

  const msg = DeviceName.create({
    ephemeralPublic: ephemeralPub.serialize(),
    syntheticIv,
    ciphertext,
  });

  return Buffer.from(DeviceName.encode(msg).finish()).toString("base64");
}
