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

export interface ServerPreKey {
  keyId: number;
  publicKey: string; // base64
}

export interface ServerSignedPreKey {
  keyId: number;
  publicKey: string;
  signature: string;
}

export interface ServerDevice {
  deviceId: number;
  registrationId: number;
  preKey?: ServerPreKey;
  signedPreKey: ServerSignedPreKey;
  pqPreKey?: ServerSignedPreKey;
}

export interface ServerKeys {
  identityKey: string; // base64
  devices: ServerDevice[];
}

function b64d(s: string) {
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
) {
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
) {
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

export function randomPadding() {
  // Matches Signal-Desktop's getRandomPadding: 1..512 random bytes.
  const lenBuf = randomBytes(2);
  const len = (lenBuf.readUInt16LE(0) & 0x1ff) + 1;
  return randomBytes(len);
}

const PADDING_BLOCK = 80;

/**
 * Pads `message` with a `0x80` terminator followed by zero bytes so that the
 * resulting length is a multiple of 80 (minus one for the terminator). Matches
 * Signal-Desktop's `padMessage`. The peer's decrypt step strips it by
 * scanning from the end for `0x80`.
 */
export function padMessage(message: Uint8Array) {
  const withTerminator = message.byteLength + 1;
  const blocks = Math.ceil(withTerminator / PADDING_BLOCK);
  const padded = new Uint8Array(blocks * PADDING_BLOCK - 1);
  padded.set(message);
  padded[message.byteLength] = 0x80;
  return padded;
}

function buildSyncRequestContent(type: number) {
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

function ciphertextTypeToServer(t: CiphertextMessageType) {
  switch (t) {
    case CiphertextMessageType.Whisper:
      return SERVER_TYPE_CIPHERTEXT;
    case CiphertextMessageType.PreKey:
      return SERVER_TYPE_PREKEY_BUNDLE;
    default:
      throw new Error(`Unsupported ciphertext type for /v1/messages: ${t}`);
  }
}

export interface OutgoingMessage {
  type: number;
  destinationDeviceId: number;
  destinationRegistrationId: number;
  content: string; // base64
}

export async function encryptContentForDevice(
  stores: ProtocolStores,
  remote: ProtocolAddress,
  localAddress: ProtocolAddress,
  plaintext: Uint8Array,
): Promise<OutgoingMessage> {
  const padded = padMessage(plaintext);
  const ciphertext = await signalEncrypt(
    padded,
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

export interface SendMessagesOptions {
  timestamp: number;
  online?: boolean;
  urgent?: boolean;
  story?: boolean;
}

/**
 * Thrown when the server reports the recipient's device list does not match
 * what we sent to. Callers (see `send.ts`) recover by removing extra sessions
 * / archiving stale sessions / refetching key bundles, then retrying.
 *
 * - 409 "mismatched devices": we sent to too many (`extraDevices`) or missed
 *   some (`missingDevices`).
 * - 410 "stale devices": some sessions are out of date and must be
 *   re-established (`staleDevices`).
 */
export class DeviceMismatchError extends Error {
  constructor(
    readonly status: 409 | 410,
    readonly extraDevices: number[],
    readonly missingDevices: number[],
    readonly staleDevices: number[],
  ) {
    super(`Device mismatch (${status})`);
    this.name = "DeviceMismatchError";
  }
}

export async function sendMessages(
  chat: Net.AuthenticatedChatConnection,
  destination: string,
  messages: OutgoingMessage[],
  opts: SendMessagesOptions,
  userAgent: string,
) {
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
    const text = res.body ? Buffer.from(res.body).toString("utf8") : "";

    let extra: number[] = [];
    let missing: number[] = [];
    let stale: number[] = [];

    try {
      const parsed = JSON.parse(text) as {
        extraDevices?: number[];
        missingDevices?: number[];
        staleDevices?: number[];
      };

      extra = parsed.extraDevices ?? [];
      missing = parsed.missingDevices ?? [];
      stale = parsed.staleDevices ?? [];
    } catch {
      /* leave arrays empty */
    }

    throw new DeviceMismatchError(res.status, extra, missing, stale);
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
) {
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
