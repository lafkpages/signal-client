import { KEMKeyPair, Net, PrivateKey } from "@signalapp/libsignal-client";
import { randomBytes } from "node:crypto";
import type { KeyPair } from "./provisioningCipher.ts";

export type SignedPreKeyJson = {
  keyId: number;
  publicKey: string; // base64
  signature: string; // base64
};

export type LinkDeviceRequest = {
  verificationCode: string; // from ProvisionMessage.provisioningCode
  accountAttributes: {
    fetchesMessages: true;
    name: string; // base64 of encrypted DeviceName proto
    registrationId: number;
    pniRegistrationId: number;
    capabilities: {
      attachmentBackfill: true;
      spqr: true;
    };
  };
  aciSignedPreKey: SignedPreKeyJson;
  pniSignedPreKey: SignedPreKeyJson;
  aciPqLastResortPreKey: SignedPreKeyJson;
  pniPqLastResortPreKey: SignedPreKeyJson;
};

export type LinkDeviceResponse = {
  uuid: string; // ACI
  pni: string; // untagged PNI (no "PNI:" prefix)
  deviceId: number;
};

function b64(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("base64");
}

function basicAuth(username: string, password: string): string {
  return "Basic " + Buffer.from(`${username}:${password}`).toString("base64");
}

function randomRegistrationId(): number {
  // Signal uses 14-bit registration IDs: [1, 0x3FFE]
  const n = randomBytes(2).readUInt16BE(0) & 0x3fff || 1;
  return n;
}

export { randomRegistrationId };

function randomKeyId(): number {
  // Signal uses 24-bit key IDs (positive, non-zero).
  let id = 0;
  while (id === 0) {
    id = randomBytes(3).readUIntBE(0, 3);
  }
  return id;
}

export function generateAccountPassword(): string {
  // Matches Signal-Desktop: 16 random bytes -> base64 -> drop trailing 2 chars
  return Buffer.from(randomBytes(16)).toString("base64").slice(0, -2);
}

export type GeneratedPreKeys = {
  signedPreKey: SignedPreKeyJson;
  pqLastResortPreKey: SignedPreKeyJson;
  signedPreKeyPrivate: PrivateKey;
  signedPreKeyId: number;
  pqLastResortPreKeyPrivate: KEMKeyPair;
  pqLastResortPreKeyId: number;
};

/**
 * Generates a signed EC pre-key and a Kyber last-resort pre-key, both signed
 * with `identityKeyPair.privateKey`.
 */
export function generatePreKeys(identityKeyPair: KeyPair): GeneratedPreKeys {
  const signedPreKeyId = randomKeyId();
  const signedPreKeyPrivate = PrivateKey.generate();
  const signedPreKeyPublic = signedPreKeyPrivate.getPublicKey();
  const signedPreKeySignature = identityKeyPair.privateKey.sign(
    signedPreKeyPublic.serialize(),
  );

  const pqLastResortPreKeyId = randomKeyId();
  const pqKeyPair = KEMKeyPair.generate();
  const pqPub = pqKeyPair.getPublicKey().serialize();
  const pqSignature = identityKeyPair.privateKey.sign(pqPub);

  return {
    signedPreKey: {
      keyId: signedPreKeyId,
      publicKey: b64(signedPreKeyPublic.serialize()),
      signature: b64(signedPreKeySignature),
    },
    pqLastResortPreKey: {
      keyId: pqLastResortPreKeyId,
      publicKey: b64(pqPub),
      signature: b64(pqSignature),
    },
    signedPreKeyPrivate,
    signedPreKeyId,
    pqLastResortPreKeyPrivate: pqKeyPair,
    pqLastResortPreKeyId,
  };
}

/**
 * Calls `PUT /v1/devices/link` over a libsignal unauthenticated chat
 * connection. `e164` is the phone number from the ProvisionMessage; `password`
 * is a freshly generated account password.
 */
export async function linkDevice(
  net: Net.Net,
  e164: string,
  password: string,
  body: LinkDeviceRequest,
  userAgent: string,
): Promise<LinkDeviceResponse> {
  const chat = await net.connectUnauthenticatedChat({
    onConnectionInterrupted: () => {},
  });

  try {
    const req: Net.ChatRequest = {
      verb: "PUT",
      path: "/v1/devices/link",
      headers: [
        ["authorization", basicAuth(e164, password)],
        ["content-type", "application/json"],
        ["user-agent", userAgent],
      ],
      body: new Uint8Array(Buffer.from(JSON.stringify(body), "utf8")),
    };
    const res = await chat.fetch(req);
    if (res.status < 200 || res.status >= 300) {
      const text = res.body ? Buffer.from(res.body).toString("utf8") : "";
      throw new Error(`PUT /v1/devices/link failed: ${res.status} ${text}`);
    }
    const text = res.body ? Buffer.from(res.body).toString("utf8") : "";
    return JSON.parse(text) as LinkDeviceResponse;
  } finally {
    await chat.disconnect();
  }
}

// ---------- Post-link: authenticated connection + prekey upload ----------

/**
 * Basic auth username after linking: "<ACI>.<deviceId>".
 */
export function authUsername(aci: string, deviceId: number): string {
  return `${aci}.${deviceId}`;
}

/**
 * Opens an authenticated chat connection. Messages and requests flow through
 * `chat.fetch(...)` and the listener. Caller is responsible for disconnecting.
 */
export async function connectAuthedChat(
  net: Net.Net,
  aci: string,
  deviceId: number,
  password: string,
  onIncoming: (envelope: Uint8Array, timestamp: number) => void,
): Promise<Net.AuthenticatedChatConnection> {
  return await net.connectAuthenticatedChat(
    authUsername(aci, deviceId),
    password,
    /* receiveStories */ false,
    {
      onConnectionInterrupted: (err) => {
        if (err) console.error("Auth chat interrupted:", err);
      },
      onIncomingMessage: (envelope, timestamp, ack) => {
        try {
          onIncoming(envelope, timestamp);
        } finally {
          ack.send(200);
        }
      },
      onQueueEmpty: () => {
        console.log("Auth chat: queue empty");
      },
      onReceivedAlerts: (alerts) => {
        if (alerts.length > 0) console.log("Server alerts:", alerts);
      },
    },
  );
}

export type OneTimePreKeyJson = {
  keyId: number;
  publicKey: string; // base64 of PublicKey.serialize()
};

export type GeneratedOneTimeKeys = {
  preKeys: OneTimePreKeyJson[];
  pqPreKeys: SignedPreKeyJson[];
  // Private halves the caller must persist to decrypt incoming messages.
  preKeyPrivates: Array<{ keyId: number; privateKey: PrivateKey }>;
  pqPreKeyPrivates: Array<{ keyId: number; keyPair: KEMKeyPair }>;
};

/**
 * Generates `count` one-time EC pre-keys and `count` one-time Kyber pre-keys.
 * Signal-Desktop uploads batches of 100.
 */
export function generateOneTimePreKeys(
  identityKeyPair: KeyPair,
  count = 100,
): GeneratedOneTimeKeys {
  const preKeys: OneTimePreKeyJson[] = [];
  const preKeyPrivates: GeneratedOneTimeKeys["preKeyPrivates"] = [];
  const pqPreKeys: SignedPreKeyJson[] = [];
  const pqPreKeyPrivates: GeneratedOneTimeKeys["pqPreKeyPrivates"] = [];

  for (let i = 0; i < count; i++) {
    const keyId = randomKeyId();
    const priv = PrivateKey.generate();
    preKeys.push({ keyId, publicKey: b64(priv.getPublicKey().serialize()) });
    preKeyPrivates.push({ keyId, privateKey: priv });
  }

  for (let i = 0; i < count; i++) {
    const keyId = randomKeyId();
    const kp = KEMKeyPair.generate();
    const pub = kp.getPublicKey().serialize();
    const sig = identityKeyPair.privateKey.sign(pub);
    pqPreKeys.push({
      keyId,
      publicKey: b64(pub),
      signature: b64(sig),
    });
    pqPreKeyPrivates.push({ keyId, keyPair: kp });
  }

  return { preKeys, pqPreKeys, preKeyPrivates, pqPreKeyPrivates };
}

export type RegisterKeysBody = {
  preKeys: OneTimePreKeyJson[];
  pqPreKeys: SignedPreKeyJson[];
  // Optional — Signal-Desktop re-sends these post-link to keep the server in
  // sync, but they were already uploaded at /v1/devices/link.
  signedPreKey?: SignedPreKeyJson;
  pqLastResortPreKey?: SignedPreKeyJson;
};

/**
 * PUT /v2/keys?identity=aci|pni — uploads one-time pre-keys (EC + Kyber) for
 * the given identity on an already-authenticated chat connection.
 */
export async function registerOneTimeKeys(
  chat: Net.UnauthenticatedChatConnection | Net.AuthenticatedChatConnection,
  identity: "aci" | "pni",
  body: RegisterKeysBody,
  userAgent: string,
): Promise<void> {
  const req: Net.ChatRequest = {
    verb: "PUT",
    path: `/v2/keys?identity=${identity}`,
    headers: [
      ["content-type", "application/json"],
      ["user-agent", userAgent],
    ],
    body: new Uint8Array(Buffer.from(JSON.stringify(body), "utf8")),
  };
  const res = await chat.fetch(req);
  if (res.status < 200 || res.status >= 300) {
    const text = res.body ? Buffer.from(res.body).toString("utf8") : "";
    throw new Error(
      `PUT /v2/keys?identity=${identity} failed: ${res.status} ${text}`,
    );
  }
}
