import type { ProtocolStores } from "./stores.ts";

import { randomBytes } from "node:crypto";

import {
  CiphertextMessageType,
  KEMPublicKey,
  Net,
  PreKeyBundle,
  processPreKeyBundle,
  ProtocolAddress,
  PublicKey,
  signalEncrypt,
} from "@signalapp/libsignal-client";

import { Content, SyncMessage, SyncRequestType } from "./protos.ts";

// ---------- Prekey bundle fetch ----------

export type ServerPreKey = {
  keyId: number;
  publicKey: string; // base64
};

export type ServerSignedPreKey = {
  keyId: number;
  publicKey: string;
  signature: string;
};

export type ServerDevice = {
  deviceId: number;
  registrationId: number;
  preKey?: ServerPreKey;
  signedPreKey: ServerSignedPreKey;
  pqPreKey?: ServerSignedPreKey;
};

export type ServerKeys = {
  identityKey: string; // base64
  devices: ServerDevice[];
};

function b64d(s: string): Uint8Array<ArrayBuffer> {
  const buf = Buffer.from(s, "base64");
  const out = new Uint8Array(buf.byteLength);
  out.set(buf);
  return out;
}

/**
 * GET /v2/keys/<serviceId>/* — returns one prekey bundle per device.
 */
export async function getKeysForServiceId(
  chat: Net.AuthenticatedChatConnection,
  serviceId: string,
  userAgent: string,
): Promise<ServerKeys> {
  const req: Net.ChatRequest = {
    verb: "GET",
    path: `/v2/keys/${serviceId}/*`,
    headers: [["user-agent", userAgent]],
  };
  const res = await chat.fetch(req);
  if (res.status < 200 || res.status >= 300) {
    const text = res.body ? Buffer.from(res.body).toString("utf8") : "";
    throw new Error(
      `GET /v2/keys/${serviceId}/* failed: ${res.status} ${text}`,
    );
  }
  const text = res.body ? Buffer.from(res.body).toString("utf8") : "";
  return JSON.parse(text) as ServerKeys;
}

// ---------- Session setup from a fetched bundle ----------

/**
 * Turns a server-side device description into a libsignal `PreKeyBundle` and
 * installs a session in the caller's stores.
 */
export async function installSessionFromDevice(
  stores: ProtocolStores,
  address: ProtocolAddress,
  identityKeyB64: string,
  device: ServerDevice,
): Promise<void> {
  if (!device.pqPreKey) {
    throw new Error(
      `Device ${address.deviceId()} has no pqPreKey — server policy change?`,
    );
  }
  const identityKey = PublicKey.deserialize(b64d(identityKeyB64));
  const signedPreKey = PublicKey.deserialize(
    b64d(device.signedPreKey.publicKey),
  );
  const preKeyPublic = device.preKey
    ? PublicKey.deserialize(b64d(device.preKey.publicKey))
    : null;
  const preKeyId = device.preKey ? device.preKey.keyId : null;
  const kyberPub = KEMPublicKey.deserialize(b64d(device.pqPreKey.publicKey));

  const bundle = PreKeyBundle.new(
    device.registrationId,
    device.deviceId,
    preKeyId,
    preKeyPublic,
    device.signedPreKey.keyId,
    signedPreKey,
    b64d(device.signedPreKey.signature),
    identityKey,
    device.pqPreKey.keyId,
    kyberPub,
    b64d(device.pqPreKey.signature),
  );

  await processPreKeyBundle(bundle, address, stores.session, stores.identity);
}

// ---------- Content building ----------

function randomPadding(): Uint8Array {
  // Matches Signal-Desktop's getRandomPadding: 1..512 random bytes.
  const lenBuf = randomBytes(2);
  const len = (lenBuf.readUInt16LE(0) & 0x1ff) + 1;
  return randomBytes(len);
}

function buildSyncRequestContent(type: number): Uint8Array<ArrayBuffer> {
  const syncMessage = SyncMessage.create({
    request: { type },
    padding: randomPadding(),
  });
  const content = Content.create({ syncMessage });
  const out = Content.encode(content).finish();
  // protobufjs returns Uint8Array<ArrayBufferLike>; copy into ArrayBuffer-backed.
  const copy = new Uint8Array(out.byteLength);
  copy.set(out);
  return copy;
}

// ---------- Encrypt + wire-format conversion ----------

// Server-side `type` field on /v1/messages payloads. These differ from
// libsignal's CiphertextMessageType enum.
const SERVER_TYPE_CIPHERTEXT = 1; // libsignal Whisper
const SERVER_TYPE_PREKEY_BUNDLE = 3; // libsignal PreKey

function ciphertextTypeToServer(t: CiphertextMessageType): number {
  switch (t) {
    case CiphertextMessageType.Whisper:
      return SERVER_TYPE_CIPHERTEXT;
    case CiphertextMessageType.PreKey:
      return SERVER_TYPE_PREKEY_BUNDLE;
    default:
      throw new Error(`Unsupported ciphertext type for /v1/messages: ${t}`);
  }
}

export type OutgoingMessage = {
  type: number;
  destinationDeviceId: number;
  destinationRegistrationId: number;
  content: string; // base64
};

export async function encryptContentForDevice(
  stores: ProtocolStores,
  remote: ProtocolAddress,
  localAddress: ProtocolAddress,
  plaintext: Uint8Array<ArrayBuffer>,
): Promise<OutgoingMessage> {
  const ciphertext = await signalEncrypt(
    plaintext,
    remote,
    localAddress,
    stores.session,
    stores.identity,
  );
  const session = await stores.session.getSession(remote);
  if (!session) throw new Error("Session disappeared after encrypt");
  // Remote registration ID must match the bundle we used to build the session.
  const destinationRegistrationId = session.remoteRegistrationId();

  return {
    type: ciphertextTypeToServer(ciphertext.type()),
    destinationDeviceId: remote.deviceId(),
    destinationRegistrationId,
    content: Buffer.from(ciphertext.serialize()).toString("base64"),
  };
}

// ---------- PUT /v1/messages/<dest> ----------

export type SendMessagesOptions = {
  timestamp: number;
  online?: boolean;
  urgent?: boolean;
  story?: boolean;
};

export async function sendMessages(
  chat: Net.AuthenticatedChatConnection,
  destination: string,
  messages: OutgoingMessage[],
  opts: SendMessagesOptions,
  userAgent: string,
): Promise<void> {
  const body = {
    messages,
    timestamp: opts.timestamp,
    online: Boolean(opts.online),
    urgent: opts.urgent ?? true,
  };
  const req: Net.ChatRequest = {
    verb: "PUT",
    path: `/v1/messages/${destination}?story=${opts.story ? "true" : "false"}`,
    headers: [
      ["content-type", "application/json"],
      ["user-agent", userAgent],
    ],
    body: new TextEncoder().encode(JSON.stringify(body)),
  };
  const res = await chat.fetch(req);
  if (res.status === 409 || res.status === 410) {
    // 409 = mismatched devices (must add/remove a session)
    // 410 = stale devices (must clear sessions and retry)
    const text = res.body ? Buffer.from(res.body).toString("utf8") : "";
    throw new Error(`Device mismatch (${res.status}): ${text}`);
  }
  if (res.status < 200 || res.status >= 300) {
    const text = res.body ? Buffer.from(res.body).toString("utf8") : "";
    throw new Error(
      `PUT /v1/messages/${destination} failed: ${res.status} ${text}`,
    );
  }
}

// ---------- Top-level: send sync requests to self ----------

/**
 * Sends SyncMessage.Request for CONTACTS, CONFIGURATION, and BLOCKED to all
 * other devices on our own ACI. The primary replies with SyncMessage.Contacts
 * (attachment pointer), Configuration, and Blocked as normal incoming
 * envelopes on the authenticated chat connection.
 */
export async function sendSyncRequests(
  chat: Net.AuthenticatedChatConnection,
  stores: ProtocolStores,
  selfAci: string,
  selfDeviceId: number,
  userAgent: string,
): Promise<void> {
  const localAddress = ProtocolAddress.new(selfAci, selfDeviceId);
  const keys = await getKeysForServiceId(chat, selfAci, userAgent);

  // Build sessions for every other device on our account.
  const remoteDevices = keys.devices.filter((d) => d.deviceId !== selfDeviceId);
  if (remoteDevices.length === 0) {
    throw new Error(
      "No other devices found on this account — nothing to sync with",
    );
  }
  const remoteAddresses: ProtocolAddress[] = [];
  for (const dev of remoteDevices) {
    const addr = ProtocolAddress.new(selfAci, dev.deviceId);
    await installSessionFromDevice(stores, addr, keys.identityKey, dev);
    remoteAddresses.push(addr);
  }

  const requests: Array<{
    label: string;
    type: number;
    urgent: boolean;
  }> = [
    { label: "contacts", type: SyncRequestType.CONTACTS, urgent: true },
    {
      label: "configuration",
      type: SyncRequestType.CONFIGURATION,
      urgent: false,
    },
    { label: "blocked", type: SyncRequestType.BLOCKED, urgent: false },
  ];

  for (const r of requests) {
    const plaintext = buildSyncRequestContent(r.type);
    const messages: OutgoingMessage[] = [];
    for (const addr of remoteAddresses) {
      messages.push(
        await encryptContentForDevice(stores, addr, localAddress, plaintext),
      );
    }
    await sendMessages(
      chat,
      selfAci,
      messages,
      { timestamp: Date.now(), urgent: r.urgent },
      userAgent,
    );
    console.log(
      `Sent sync request: ${r.label} -> ${messages.length} device(s)`,
    );
  }
}
