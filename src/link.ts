import { Net } from "@signalapp/libsignal-client";
import qrcode from "qrcode-terminal";

import { version } from "../package.json";
import { fetchAndDecryptAttachment } from "./attachments.ts";
import {
  connectAuthedChat,
  generateAccountPassword,
  generateOneTimePreKeys,
  generatePreKeys,
  linkDevice,
  randomRegistrationId,
  registerOneTimeKeys,
  type LinkDeviceRequest,
} from "./chatApi.ts";
import { parseContactDetailsStream } from "./contacts.ts";
import { decryptEnvelope, parseEnvelope } from "./decrypt.ts";
import { encryptDeviceName } from "./deviceName.ts";
import {
  Content,
  EnvelopeType,
  type IAttachmentPointer,
  type IContent,
} from "./protos.ts";
import {
  ProvisioningCipher,
  type ProvisionDecryptResult,
} from "./provisioningCipher.ts";
import {
  b64,
  loadPrivateKey,
  loadState,
  saveState,
  type LinkedState,
} from "./state.ts";
import { createStores, type ProtocolStores } from "./stores.ts";
import { sendSyncRequests } from "./sync.ts";

const USER_AGENT = `@luisafk/libsignal-test/${version}`;
const DEVICE_NAME = `@luisafk/libsignal-test`;
const STATE_FILE = "state.json";
const STORE_DIR = "store";

// Narrow, use-site-driven view of the decoded Content proto. We only inspect
// the presence of each top-level message and, for SyncMessage, the Contacts
// attachment pointer, so there's no need to restate the full schema here.

function decodeContent(plaintext: Uint8Array): IContent | null {
  try {
    // Pass through toObject to get real Uint8Array byte fields (not base64).
    const msg = Content.decode(plaintext);
    return Content.toObject(msg, {
      longs: Number,
      bytes: Array, // returns Uint8Array
      defaults: false,
    });
  } catch {
    return null;
  }
}

function describeContent(content: IContent | null, size: number): string {
  if (!content) return `<${size} bytes, failed to decode as Content>`;
  const keys = Object.keys(content);
  if (content.syncMessage) {
    const smKeys = Object.keys(content.syncMessage);
    return `Content{syncMessage:{${smKeys.join(",")}}}`;
  }
  if (content.dataMessage) return "Content{dataMessage}";
  if (content.typingMessage) return "Content{typingMessage}";
  if (content.receiptMessage) return "Content{receiptMessage}";
  if (content.callMessage) return "Content{callMessage}";
  return `Content{${keys.join(",")}}`;
}

async function handleContactsSync(
  ptr: IAttachmentPointer,
  complete: boolean,
): Promise<void> {
  if (!ptr.cdnKey && (ptr.cdnId === undefined || ptr.cdnId === null)) {
    console.log("SyncMessage.Contacts: empty pointer; nothing to download.");
    return;
  }
  console.log(
    `SyncMessage.Contacts: downloading attachment (cdn=${ptr.cdnNumber ?? 0}, size=${ptr.size ?? "?"}, complete=${complete})...`,
  );
  const plaintext = await fetchAndDecryptAttachment(ptr, USER_AGENT);
  const contacts = parseContactDetailsStream(plaintext);
  console.log(`SyncMessage.Contacts: parsed ${contacts.length} contacts:`);
  for (const c of contacts) {
    const id = c.aci ?? c.number ?? "(unknown)";
    const name = c.name ? ` "${c.name}"` : "";
    const avatar = c.avatar ? ` +avatar(${c.avatar.bytes.length}B)` : "";
    console.log(`  - ${id}${name}${avatar}`);
  }
}

function makeIncomingHandler(
  getStores: () => ProtocolStores | null,
  localAci: string,
  localDeviceId: number,
): (envelope: Uint8Array, timestamp: number) => void {
  return (envelope, timestamp) => {
    const stores = getStores();
    if (!stores) {
      // Handshake race: an envelope arrived before we finished setting up.
      console.log(
        "Incoming envelope before stores ready; skipping decrypt:",
        new Date(timestamp).toISOString(),
      );
      return;
    }
    void (async () => {
      try {
        const result = await decryptEnvelope(
          envelope,
          stores,
          localAci,
          localDeviceId,
        );
        const hdr = `type=${result.envelope.type}`;
        const from = result.sealedSender
          ? `${result.sealedSender.senderUuid}.${result.sealedSender.senderDeviceId}`
          : result.envelope.sourceServiceId
            ? `${result.envelope.sourceServiceId}.${result.envelope.sourceDeviceId}`
            : "unknown";
        if (result.plaintext) {
          const content = decodeContent(result.plaintext);
          console.log(
            `Envelope ${hdr} from ${from}:`,
            describeContent(content, result.plaintext.byteLength),
          );
          const contacts = content?.syncMessage?.contacts;
          if (contacts?.blob) {
            try {
              await handleContactsSync(
                contacts.blob,
                contacts.complete ?? false,
              );
            } catch (e) {
              console.error("Contacts sync handling failed:", e);
            }
          }
        } else if (
          result.envelope.type === EnvelopeType.SERVER_DELIVERY_RECEIPT
        ) {
          console.log(`Server delivery receipt for ${from}`);
        } else {
          console.log(`Envelope ${hdr} from ${from} (empty)`);
        }
      } catch (e) {
        // We don't have a decrypted envelope here, but we can still peek at
        // the outer Envelope proto to show what type of message failed.
        let outerType = "?";
        try {
          outerType = `type=${parseEnvelope(envelope).type}`;
        } catch {
          /* ignore */
        }
        const msg = e instanceof Error ? e.message : String(e);
        console.error(`decrypt failed (${outerType}): ${msg}`);
      }
    })();
  };
}

function buildQrUrl(
  address: string,
  publicKey: Uint8Array,
  capabilities: string[],
): string {
  const pub = Buffer.from(publicKey).toString("base64");
  const caps = capabilities.join(",");
  const params = new URLSearchParams({
    uuid: address,
    pub_key: pub,
    capabilities: caps,
  });
  return `sgnl://linkdevice?${params.toString()}`;
}

/** Waits for the first provisioning envelope on a brand-new provisioning WS. */
async function awaitEnvelope(
  net: Net.Net,
  cipher: ProvisioningCipher,
  onQrUrl: (url: string) => void,
): Promise<ProvisionDecryptResult> {
  return await new Promise<ProvisionDecryptResult>((resolve, reject) => {
    let conn: Net.ProvisioningConnection | undefined;
    let settled = false;

    const finish = (err: Error | null, value?: ProvisionDecryptResult) => {
      if (settled) return;
      settled = true;
      conn?.disconnect().catch(() => {});
      if (err) reject(err);
      else resolve(value!);
    };

    net
      .connectProvisioning({
        onConnectionInterrupted: (err) => {
          finish(err ?? new Error("Provisioning connection interrupted"));
        },
        onReceivedAddress: (address, ack) => {
          try {
            const url = buildQrUrl(address, cipher.publicKey.serialize(), []);
            onQrUrl(url);
            ack.send(200);
          } catch (e) {
            finish(e as Error);
          }
        },
        onReceivedEnvelope: (envelope, ack) => {
          try {
            // Envelope bytes here are the serialized ProvisionEnvelope proto.
            const msg = cipher.decrypt(envelope);
            ack.send(200);
            finish(null, msg);
          } catch (e) {
            finish(e as Error);
          }
        },
      })
      .then((c) => {
        conn = c;
      })
      .catch((e) => finish(e as Error));
  });
}

async function main(): Promise<void> {
  // Bun/Node may drop out of the event loop if libsignal's Rust runtime
  // doesn't register a keep-alive handle. Park a long timer so we stay
  // alive until main() completes (or a fatal error).
  const keepAlive = setInterval(() => {}, 1 << 30);
  try {
    await runMain();
  } finally {
    clearInterval(keepAlive);
  }
}

async function runMain(): Promise<void> {
  const net = new Net.Net({
    env: Net.Environment.Production,
    userAgent: USER_AGENT,
  });

  // ---- Resume path: if we've linked before, just reconnect ----
  const existing = loadState(STATE_FILE);
  if (existing) {
    console.log(
      `Found existing state for ${existing.aci} (device ${existing.deviceId}); reconnecting...`,
    );
    const identityPrivate = loadPrivateKey(existing.aciIdentityPrivate);
    // Stores auto-rehydrate from STORE_DIR/*.json.
    const stores = createStores(
      identityPrivate,
      existing.registrationId,
      STORE_DIR,
    );
    const authChat = await connectAuthedChat(
      net,
      existing.aci,
      existing.deviceId,
      existing.password,
      makeIncomingHandler(() => stores, existing.aci, existing.deviceId),
    );
    console.log(
      "Reconnected. Listening for incoming envelopes. Ctrl+C to quit.",
    );
    await new Promise<void>(() => {
      /* never resolves */
    });
    void authChat;
    return;
  }

  const cipher = new ProvisioningCipher();

  console.log("Opening provisioning connection...");
  const msg = await awaitEnvelope(net, cipher, (url) => {
    console.log("\nScan this QR with the Signal mobile app:");
    console.log("(Settings -> Linked devices -> Link new device)\n");
    qrcode.generate(url, { small: true });
    console.log("\nRaw URL (if scanning fails):", url, "\n");
  });

  console.log("Got ProvisionMessage:", {
    aci: msg.aci,
    pni: msg.pni,
    number: msg.number,
    userAgent: msg.userAgent,
    hasMasterKey: !!msg.masterKey,
    hasAEP: !!msg.accountEntropyPool,
    hasProfileKey: !!msg.profileKey,
    hasEphemeralBackupKey: !!msg.ephemeralBackupKey,
  });

  if (!msg.number) throw new Error("ProvisionMessage missing number");
  if (!msg.provisioningCode)
    throw new Error("ProvisionMessage missing provisioningCode");
  if (!msg.pniKeyPair)
    throw new Error("ProvisionMessage missing pni identity key");

  const password = generateAccountPassword();
  const registrationId = randomRegistrationId();
  const pniRegistrationId = randomRegistrationId();

  const aciKeys = generatePreKeys(msg.aciKeyPair);
  const pniKeys = generatePreKeys(msg.pniKeyPair);

  const encryptedName = encryptDeviceName(
    DEVICE_NAME,
    msg.aciKeyPair.publicKey,
  );

  const body: LinkDeviceRequest = {
    verificationCode: msg.provisioningCode,
    accountAttributes: {
      fetchesMessages: true,
      name: encryptedName,
      registrationId,
      pniRegistrationId,
      capabilities: { attachmentBackfill: true, spqr: true },
    },
    aciSignedPreKey: aciKeys.signedPreKey,
    pniSignedPreKey: pniKeys.signedPreKey,
    aciPqLastResortPreKey: aciKeys.pqLastResortPreKey,
    pniPqLastResortPreKey: pniKeys.pqLastResortPreKey,
  };

  console.log("Calling PUT /v1/devices/link ...");
  const result = await linkDevice(net, msg.number, password, body, USER_AGENT);
  console.log("Linked!", result);

  // ---- Upload 100 one-time pre-keys per identity ----
  console.log("Opening authenticated chat connection...");
  // `stores` is created later (after we have aciOneTime etc.) but the chat
  // handler is registered now. Use a mutable holder so incoming envelopes
  // that arrive before setup completes are logged and skipped.
  let storesRef: ProtocolStores | null = null;
  const authChat = await connectAuthedChat(
    net,
    result.uuid,
    result.deviceId,
    password,
    makeIncomingHandler(() => storesRef, result.uuid, result.deviceId),
  );

  const aciOneTime = generateOneTimePreKeys(msg.aciKeyPair, 100);
  const pniOneTime = generateOneTimePreKeys(msg.pniKeyPair, 100);

  console.log("Uploading one-time pre-keys...");
  await registerOneTimeKeys(
    authChat,
    "aci",
    { preKeys: aciOneTime.preKeys, pqPreKeys: aciOneTime.pqPreKeys },
    USER_AGENT,
  );
  await registerOneTimeKeys(
    authChat,
    "pni",
    { preKeys: pniOneTime.preKeys, pqPreKeys: pniOneTime.pqPreKeys },
    USER_AGENT,
  );
  console.log("One-time pre-keys uploaded.");

  // ---- Persist everything we'll need later ----
  const state: LinkedState = {
    aci: result.uuid,
    pni: msg.pni,
    number: msg.number,
    deviceId: result.deviceId,
    password,
    registrationId,
    pniRegistrationId,
    userAgent: msg.userAgent,
    readReceipts: msg.readReceipts ?? false,

    aciIdentityPrivate: b64(msg.aciKeyPair.privateKey.serialize()),
    pniIdentityPrivate: b64(msg.pniKeyPair.privateKey.serialize()),

    profileKey: msg.profileKey ? b64(msg.profileKey) : undefined,
    masterKey: msg.masterKey ? b64(msg.masterKey) : undefined,
    accountEntropyPool: msg.accountEntropyPool,
    ephemeralBackupKey: msg.ephemeralBackupKey
      ? b64(msg.ephemeralBackupKey)
      : undefined,
    mediaRootBackupKey: msg.mediaRootBackupKey
      ? b64(msg.mediaRootBackupKey)
      : undefined,
  };
  saveState(STATE_FILE, state);
  console.log(`Saved state to ${STATE_FILE}`);

  // ---- Populate an in-memory protocol store for outgoing messages ----
  // Only the ACI identity is needed to send sync-requests to self.
  // Sessions and identities persist under STORE_DIR so a restart can skip
  // the QR flow entirely via the resume path above.
  const stores = createStores(
    msg.aciKeyPair.privateKey,
    registrationId,
    STORE_DIR,
  );
  storesRef = stores;
  // Pre-populate our own pre-key stores so incoming messages from other
  // devices can be decrypted later (not wired up in this CLI, but kept here
  // so the stored keys match what we uploaded to the server).
  stores.signedPreKey.add(
    aciKeys.signedPreKeyId,
    Date.now(),
    aciKeys.signedPreKeyPrivate,
    Buffer.from(aciKeys.signedPreKey.signature, "base64"),
  );
  stores.kyberPreKey.add(
    aciKeys.pqLastResortPreKeyId,
    Date.now(),
    aciKeys.pqLastResortPreKeyPrivate,
    Buffer.from(aciKeys.pqLastResortPreKey.signature, "base64"),
  );
  for (const k of aciOneTime.preKeyPrivates) {
    stores.preKey.add(k.keyId, k.privateKey);
  }
  for (const k of aciOneTime.pqPreKeyPrivates) {
    stores.kyberPreKey.add(
      k.keyId,
      Date.now(),
      k.keyPair,
      // Signatures on one-time Kyber pre-keys are only needed by the sender
      // (to build a PreKeyBundle). The receiver-side store just needs the
      // key material for decryption.
      new Uint8Array(),
    );
  }

  // ---- Send sync requests to the primary (Contacts / Configuration / Blocked) ----
  try {
    await sendSyncRequests(
      authChat,
      stores,
      result.uuid,
      result.deviceId,
      USER_AGENT,
    );
    console.log(
      "Sync requests sent. Primary device will reply via incoming envelopes.",
    );
  } catch (e) {
    console.error("sendSyncRequests failed:", e);
  }

  // ---- Listen for incoming messages ----
  //
  // Envelopes arriving on `authChat` are decrypted by `makeIncomingHandler`
  // above, including SyncMessage.Contacts (attachment download + parse).
  // Still TODO:
  //   - Storage-service sync: GET /v1/storage/auth, then manifest + records,
  //     using an AES-GCM-SIV record key derived via HKDF from masterKey/AEP.
  console.log("\nListening for incoming envelopes. Ctrl+C to quit.");
  await new Promise<void>(() => {
    /* never resolves */
  });
  void authChat;
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});

process.on("unhandledRejection", (reason) => {
  console.error("UNHANDLED REJECTION:", reason);
  process.exit(1);
});
process.on("uncaughtException", (err) => {
  console.error("UNCAUGHT EXCEPTION:", err);
  process.exit(1);
});
