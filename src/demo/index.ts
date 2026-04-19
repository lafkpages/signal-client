// Demo CLI: same behaviour as the old src/link.ts entrypoint.
//
//   bun run src/demo/index.ts
//
// On first run: opens a provisioning websocket, prints a QR for the Signal
// mobile app to scan, then completes linking and persists state to
// `state.json` + `store/`. Subsequent runs reconnect using that state.
//
// Once connected we print incoming envelopes (decrypted) in a human-readable
// form and download any SyncMessage.Contacts attachment we receive.

import qrcode from "qrcode-terminal";

import { version } from "../../package.json";
import { fetchAndDecryptAttachment } from "../attachments.ts";
import { SignalClient, type IncomingMessage } from "../client.ts";
import { parseContactDetailsStream } from "../contacts.ts";
import {
  EnvelopeType,
  ReceiptType,
  type IAttachmentPointer,
  type IContent,
} from "../protos.ts";

const USER_AGENT = `@luisafk/signal-client/${version}`;
const DEVICE_NAME = `@luisafk/signal-client`;
const STATE_FILE = "state.json";
const STORE_DIR = "store";

// ---------- Pretty-printing helpers ----------

function fmtTimestamp(ts: unknown): string {
  if (typeof ts !== "number" || !Number.isFinite(ts) || ts <= 0) return "?";
  return new Date(ts).toISOString();
}

function describeDataMessage(dm: NonNullable<IContent["dataMessage"]>): string {
  const parts: string[] = [];
  if (typeof dm.body === "string")
    parts.push(`body=${JSON.stringify(dm.body)}`);
  if (dm.attachments?.length)
    parts.push(`attachments=${dm.attachments.length}`);
  if (dm.reaction) {
    const r = dm.reaction;
    parts.push(
      `reaction=${JSON.stringify(r.emoji ?? "")}${r.remove ? "(remove)" : ""}->${fmtTimestamp(r.targetSentTimestamp)}`,
    );
  }
  if (dm.delete)
    parts.push(`delete->${fmtTimestamp(dm.delete.targetSentTimestamp)}`);
  if (dm.quote) parts.push(`quote->${fmtTimestamp(dm.quote.id)}`);
  if (dm.sticker) parts.push("sticker");
  if (dm.groupV2) parts.push("groupV2");
  if (dm.payment) parts.push("payment");
  if (typeof dm.expireTimer === "number" && dm.expireTimer > 0) {
    parts.push(`expireTimer=${dm.expireTimer}s`);
  }
  if (typeof dm.flags === "number" && dm.flags !== 0) {
    parts.push(`flags=0x${dm.flags.toString(16)}`);
  }
  if (typeof dm.timestamp === "number") {
    parts.push(`ts=${fmtTimestamp(dm.timestamp)}`);
  }
  return parts.length ? parts.join(" ") : "(empty)";
}

function describeSyncMessage(sm: NonNullable<IContent["syncMessage"]>): string {
  if (sm.sent) {
    const dest = sm.sent.destinationServiceId ?? "(self)";
    const ts = fmtTimestamp(sm.sent.timestamp);
    if (sm.sent.message) {
      return `sent->${dest} @${ts} { ${describeDataMessage(sm.sent.message)} }`;
    }
    if (sm.sent.editMessage?.dataMessage) {
      return `sent.edit->${dest} @${ts} { ${describeDataMessage(sm.sent.editMessage.dataMessage)} }`;
    }
    return `sent->${dest} @${ts} (no message)`;
  }
  if (sm.read?.length) {
    return `read x${sm.read.length} (latest @${fmtTimestamp(sm.read[sm.read.length - 1]?.timestamp)})`;
  }
  if (sm.viewed?.length) {
    return `viewed x${sm.viewed.length}`;
  }
  if (sm.contacts) return "contacts (attachment)";
  if (sm.blocked) return `blocked (acis=${sm.blocked.acis?.length ?? 0})`;
  if (sm.configuration) return "configuration";
  if (sm.request) return `request type=${sm.request.type}`;
  if (sm.fetchLatest) return `fetchLatest type=${sm.fetchLatest.type}`;
  if (sm.messageRequestResponse) return "messageRequestResponse";
  if (sm.keys) return "keys";
  if (sm.viewOnceOpen) return "viewOnceOpen";
  if (sm.callEvent) return "callEvent";
  return Object.keys(sm).join(",") || "(empty)";
}

function describeContent(content: IContent | null, size: number): string {
  if (!content) return `<${size} bytes, failed to decode as Content>`;
  if (content.syncMessage) {
    return `SyncMessage{ ${describeSyncMessage(content.syncMessage)} }`;
  }
  if (content.dataMessage) {
    return `DataMessage{ ${describeDataMessage(content.dataMessage)} }`;
  }
  if (content.typingMessage) {
    const t = content.typingMessage;
    return `TypingMessage{ action=${t.action} @${fmtTimestamp(t.timestamp)} }`;
  }
  if (content.receiptMessage) {
    const r = content.receiptMessage;
    const typeName = r.type != null ? (ReceiptType[r.type] ?? r.type) : "?";
    const tss = (r.timestamp ?? []) as Array<number | { toNumber(): number }>;
    return `ReceiptMessage{ type=${typeName} for=[${tss.map((t) => fmtTimestamp(typeof t === "number" ? t : t.toNumber())).join(",")}] }`;
  }
  if (content.callMessage) return "CallMessage";
  if (content.nullMessage) return "NullMessage";
  if (content.storyMessage) return "StoryMessage";
  if (content.editMessage?.dataMessage) {
    return `EditMessage->${fmtTimestamp(content.editMessage.targetSentTimestamp)} { ${describeDataMessage(content.editMessage.dataMessage)} }`;
  }
  return `Content{${Object.keys(content).join(",")}}`;
}

// ---------- Side-effects on incoming messages ----------

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

function logIncoming(m: IncomingMessage): void {
  const from = `${m.senderServiceId}.${m.senderDeviceId}`;
  console.log(
    `Envelope type=${m.envelopeType} from ${from}:`,
    describeContent(m.content, m.plaintext?.byteLength ?? 0),
  );
  const contacts = m.content?.syncMessage?.contacts;
  if (contacts?.blob) {
    void handleContactsSync(contacts.blob, contacts.complete ?? false).catch(
      (e) => console.error("Contacts sync handling failed:", e),
    );
  }
}

// ---------- Entrypoint ----------

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
  const client = new SignalClient({
    userAgent: USER_AGENT,
    deviceName: DEVICE_NAME,
    stateFile: STATE_FILE,
    storeDir: STORE_DIR,
  });

  // Wire up event listeners *before* we connect, so we don't miss anything.
  client.on("message", logIncoming);
  client.on("serverReceipt", (env) => {
    const from = env.sourceServiceId
      ? `${env.sourceServiceId}.${env.sourceDeviceId}`
      : "unknown";
    console.log(`Server delivery receipt for ${from}`);
  });
  client.on("decryptError", (err, outerType) => {
    const msg = err instanceof Error ? err.message : String(err);
    console.error(
      `decrypt failed (type=${outerType ?? "?"}): ${msg}`,
      outerType === EnvelopeType.SERVER_DELIVERY_RECEIPT ? "(receipt)" : "",
    );
  });
  client.on("queueEmpty", () => console.log("Auth chat: queue empty"));
  client.on("interrupted", (err) => {
    if (err) console.error("Auth chat interrupted:", err);
  });
  client.on("alerts", (alerts) => console.log("Server alerts:", alerts));

  if (!client.isLinked()) {
    console.log("Opening provisioning connection...");
    const state = await client.link({
      onQrUrl: (url) => {
        console.log("\nScan this QR with the Signal mobile app:");
        console.log("(Settings -> Linked devices -> Link new device)\n");
        qrcode.generate(url, { small: true });
        console.log("\nRaw URL (if scanning fails):", url, "\n");
      },
    });
    console.log("Linked!", {
      aci: state.aci,
      pni: state.pni,
      deviceId: state.deviceId,
    });
    console.log(`Saved state to ${STATE_FILE}`);

    await client.connect();

    try {
      await client.requestSync();
      console.log(
        "Sync requests sent. Primary device will reply via incoming envelopes.",
      );
    } catch (e) {
      console.error("requestSync failed:", e);
    }
  } else {
    console.log(
      `Found existing state for ${client.aci} (device ${client.deviceId}); reconnecting...`,
    );
    await client.connect();
    console.log("Reconnected.");
  }

  console.log("Listening for incoming envelopes. Ctrl+C to quit.");
  await new Promise<void>(() => {
    /* never resolves */
  });
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
