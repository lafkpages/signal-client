import type { IProvisionEnvelope, IProvisionMessage } from "./protos.ts";

import {
  createDecipheriv,
  createHmac,
  hkdfSync,
  timingSafeEqual,
} from "node:crypto";

import { PrivateKey, PublicKey } from "@signalapp/libsignal-client";

import { ProvisionEnvelope, ProvisionMessage } from "./protos.ts";

export interface KeyPair {
  privateKey: PrivateKey;
  publicKey: PublicKey;
}

export interface ProvisionDecryptResult {
  aciKeyPair: KeyPair;
  pniKeyPair?: KeyPair | undefined;
  number?: string | undefined;
  aci: string; // tagged UUID string
  pni: string; // tagged PNI:<uuid>
  provisioningCode?: string | undefined;
  userAgent?: string | undefined;
  readReceipts?: boolean | undefined;
  profileKey?: Uint8Array | undefined;
  masterKey?: Uint8Array | undefined;
  accountEntropyPool?: string | undefined;
  mediaRootBackupKey?: Uint8Array | undefined;
  ephemeralBackupKey?: Uint8Array | undefined;
}

// HKDF-SHA256 with zero salt and the Signal provisioning info string, producing
// 64 bytes: cipherKey (32) || macKey (32).
function deriveProvisioningKeys(sharedSecret: Uint8Array) {
  const out = hkdfSync(
    "sha256",
    sharedSecret,
    new Uint8Array(32), // salt
    Buffer.from("TextSecure Provisioning Message", "utf8"),
    64,
  );

  const buf = Buffer.from(out);

  return {
    cipherKey: buf.subarray(0, 32),
    macKey: buf.subarray(32, 64),
  };
}

function verifyHmac(data: Uint8Array, macKey: Buffer, expectedMac: Uint8Array) {
  const computed = createHmac("sha256", macKey).update(data).digest();

  if (expectedMac.byteLength !== computed.length) {
    throw new Error("Bad MAC length");
  }

  if (!timingSafeEqual(computed, Buffer.from(expectedMac))) {
    throw new Error("Bad MAC on ProvisioningMessage");
  }
}

function aes256CbcDecrypt(key: Buffer, iv: Uint8Array, ct: Uint8Array) {
  const d = createDecipheriv("aes-256-cbc", key, Buffer.from(iv));
  return Buffer.concat([d.update(Buffer.from(ct)), d.final()]);
}

function uuidBytesToString(b: Uint8Array) {
  if (b.length !== 16) throw new Error("Bad UUID byte length");

  const h = Buffer.from(b).toString("hex");

  return (
    `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-` +
    `${h.slice(16, 20)}-${h.slice(20, 32)}`
  );
}

export class ProvisioningCipher {
  public readonly privateKey;
  public readonly publicKey;

  constructor() {
    this.privateKey = PrivateKey.generate();
    this.publicKey = this.privateKey.getPublicKey();
  }

  /**
   * Decrypts a serialized ProvisionEnvelope received over the provisioning
   * WebSocket. Mirrors ts/textsecure/ProvisioningCipher.node.ts from
   * Signal-Desktop.
   */
  decrypt(envelopeBytes: Uint8Array): ProvisionDecryptResult {
    // protobufjs decode() preserves bytes fields as Uint8Array on the
    // message instance (toJSON() would base64-encode them).
    const rawEnv: IProvisionEnvelope = ProvisionEnvelope.decode(envelopeBytes);

    if (!rawEnv.publicKey)
      throw new Error("Missing publicKey in ProvisionEnvelope");
    if (!rawEnv.body) throw new Error("Missing body in ProvisionEnvelope");

    const message = rawEnv.body;
    if (message[0] !== 1) {
      throw new Error("Bad version number on ProvisioningMessage");
    }

    const iv = message.subarray(1, 17);
    const mac = message.subarray(message.byteLength - 32);
    const ivAndCiphertext = message.subarray(0, message.byteLength - 32);
    const ciphertext = message.subarray(17, message.byteLength - 32);

    // ECDH(theirEphemeralPub, ourPriv). libsignal's PrivateKey.agree does
    // exactly the X25519 agreement Signal-Desktop uses in calculateAgreement.
    const theirPub = PublicKey.deserialize(Buffer.from(rawEnv.publicKey));
    const shared = this.privateKey.agree(theirPub);

    const { cipherKey, macKey } = deriveProvisioningKeys(shared);
    verifyHmac(ivAndCiphertext, macKey, mac);
    const plaintext = aes256CbcDecrypt(cipherKey, iv, ciphertext);

    const msg: IProvisionMessage = ProvisionMessage.decode(plaintext);

    if (!msg.aciIdentityKeyPrivate) {
      throw new Error("Missing aciIdentityKeyPrivate in ProvisionMessage");
    }

    const aciPriv = PrivateKey.deserialize(
      Buffer.from(msg.aciIdentityKeyPrivate),
    );
    const aciKeyPair: KeyPair = {
      privateKey: aciPriv,
      publicKey: aciPriv.getPublicKey(),
    };

    let pniKeyPair: KeyPair | undefined;
    if (msg.pniIdentityKeyPrivate && msg.pniIdentityKeyPrivate.length > 0) {
      const pniPriv = PrivateKey.deserialize(
        Buffer.from(msg.pniIdentityKeyPrivate),
      );
      pniKeyPair = { privateKey: pniPriv, publicKey: pniPriv.getPublicKey() };
    }

    let aci: string;
    let pni: string;
    if (msg.aciBinary?.length === 16 && msg.pniBinary?.length === 16) {
      aci = uuidBytesToString(msg.aciBinary);
      pni = `PNI:${uuidBytesToString(msg.pniBinary)}`;
    } else if (msg.aci && msg.pni) {
      aci = msg.aci;
      pni = `PNI:${msg.pni}`;
    } else {
      throw new Error("Missing aci/pni in ProvisionMessage");
    }

    return {
      aciKeyPair,
      pniKeyPair,
      number: msg.number ?? undefined,
      aci,
      pni,
      provisioningCode: msg.provisioningCode ?? undefined,
      userAgent: msg.userAgent ?? undefined,
      readReceipts: msg.readReceipts ?? false,
      profileKey:
        msg.profileKey && msg.profileKey.length > 0
          ? msg.profileKey
          : undefined,
      masterKey:
        msg.masterKey && msg.masterKey.length > 0 ? msg.masterKey : undefined,
      ephemeralBackupKey:
        msg.ephemeralBackupKey && msg.ephemeralBackupKey.length > 0
          ? msg.ephemeralBackupKey
          : undefined,
      mediaRootBackupKey:
        msg.mediaRootBackupKey && msg.mediaRootBackupKey.length > 0
          ? msg.mediaRootBackupKey
          : undefined,
      accountEntropyPool: msg.accountEntropyPool || undefined,
    };
  }
}
