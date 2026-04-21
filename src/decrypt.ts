// Incoming envelope decryption.
//
// Dispatches on `Envelope.type`:
//   - DOUBLE_RATCHET (1)      -> signalDecrypt
//   - PREKEY_MESSAGE (3)      -> signalDecryptPreKey
//   - SERVER_DELIVERY_RECEIPT (5) -> no content; returns null
//   - UNIDENTIFIED_SENDER (6) -> sealedSenderDecryptMessage
//   - PLAINTEXT_CONTENT (8)   -> PlaintextContent.deserialize; inner Content
//                                must contain only `decryptionErrorMessage`
//                                (Signal spec: plaintext envelopes never
//                                carry "real" message content).
//
// The returned plaintext is the inner `Content` proto bytes with the trailing
// `0x80 00...00` padding stripped.

import {
  PlaintextContent,
  PreKeySignalMessage,
  ProtocolAddress,
  PublicKey,
  sealedSenderDecryptMessage,
  signalDecrypt,
  signalDecryptPreKey,
  SignalMessage,
} from "@signalapp/libsignal-client";

import { Content, Envelope, EnvelopeType } from "./protos.ts";
import type { ProtocolStores } from "./stores.ts";

// Signal production "unidentified delivery" trust roots, as used by
// Signal-Desktop config/production.json -> serverTrustRoots. Multiple roots
// are published; any may sign a sealed-sender certificate, so we try each.
const UD_TRUST_ROOTS_B64 = [
  "BXu6QIKVz5MA8gstzfOgRQGqyLqOwNKHL6INkv3IHWMF",
  "BUkY0I+9+oPgDCn4+Ac6Iu813yvqkDr/ga8DzLxFxuk6",
];

function toArrayBufferUint8(src: Uint8Array): Uint8Array<ArrayBuffer> {
  const out = new Uint8Array(src.byteLength);
  out.set(src);
  return out;
}

let _trustRoots: PublicKey[] | undefined;
function trustRoots(): PublicKey[] {
  if (!_trustRoots) {
    _trustRoots = UD_TRUST_ROOTS_B64.map((b64) =>
      PublicKey.deserialize(toArrayBufferUint8(Buffer.from(b64, "base64"))),
    );
  }
  return _trustRoots;
}

function unpad(padded: Uint8Array): Uint8Array {
  for (let i = padded.length - 1; i >= 0; i--) {
    const b = padded[i];
    if (b === 0x80) return padded.subarray(0, i);
    if (b !== 0x00) throw new Error("Invalid padding");
  }
  return padded;
}

export type ParsedEnvelope = {
  type: number;
  sourceServiceId?: string;
  sourceDeviceId?: number;
  destinationServiceId?: string;
  timestamp: number;
  serverGuid?: string;
  content?: Uint8Array;
  urgent?: boolean;
  story?: boolean;
};

export function parseEnvelope(bytes: Uint8Array): ParsedEnvelope {
  const msg = Envelope.decode(bytes);
  // NOTE: do NOT pass `bytes: Array` here — protobufjs interprets that as
  // "return number[]", not Uint8Array. Omitting the option gives us a Node
  // Buffer (which is a Uint8Array subclass) with a real `.byteLength`.
  const decoded = Envelope.toObject(msg, {
    longs: Number,
    defaults: false,
  });
  // `longs: Number` coerces int64 fields to plain numbers despite the
  // generated type still listing `number | Long | null`.
  const clientTs = decoded.clientTimestamp as number | null | undefined;
  const serverTs = decoded.serverTimestamp as number | null | undefined;
  return {
    type: decoded.type ?? 0,
    sourceServiceId: decoded.sourceServiceId ?? undefined,
    sourceDeviceId: decoded.sourceDeviceId ?? undefined,
    destinationServiceId: decoded.destinationServiceId ?? undefined,
    timestamp: serverTs ?? clientTs ?? 0,
    serverGuid: decoded.serverGuid ?? undefined,
    content: decoded.content ?? undefined,
    urgent: decoded.urgent ?? undefined,
    story: decoded.story ?? undefined,
  };
}

export type DecryptedEnvelope = {
  envelope: ParsedEnvelope;
  plaintext: Uint8Array | null;
  wasEncrypted: boolean;
  sealedSender?: {
    senderUuid: string;
    senderDeviceId: number;
  };
  /**
   * Only set for envelope type PLAINTEXT_CONTENT, which per the Signal
   * protocol is reserved exclusively for unauthenticated ratchet-reset
   * hints. Raw serialized `DecryptionErrorMessage` bytes; never message
   * content. When this is set, `plaintext` is null.
   */
  decryptionErrorMessage?: Uint8Array;
};

export async function decryptEnvelope(
  envelopeBytes: Uint8Array,
  stores: ProtocolStores,
  localAci: string,
  localDeviceId: number,
): Promise<DecryptedEnvelope> {
  const envelope = parseEnvelope(envelopeBytes);
  const content = envelope.content
    ? toArrayBufferUint8(envelope.content)
    : undefined;

  switch (envelope.type) {
    case EnvelopeType.SERVER_DELIVERY_RECEIPT: {
      return { envelope, plaintext: null, wasEncrypted: false };
    }

    case EnvelopeType.PLAINTEXT_CONTENT: {
      if (!content) throw new Error("PLAINTEXT_CONTENT envelope has no body");
      // PLAINTEXT_CONTENT is unauthenticated: there is no ratchet, no sealed
      // sender certificate, and no binding of the body to the sender's
      // identity key. The server-stamped `sourceServiceId` is the only sender
      // hint, and it must be present — an anonymous plaintext envelope would
      // not even be attributable.
      if (!envelope.sourceServiceId || !envelope.sourceDeviceId) {
        throw new Error("PLAINTEXT_CONTENT envelope missing sender info");
      }
      const msg = PlaintextContent.deserialize(content);
      const inner = unpad(msg.body());
      // Parse the inner Content and strictly allow-list what may appear.
      // Per SignalService.proto: "plaintext messages never have 'real'
      // message content generated by users". In practice the only field
      // produced here is `decryptionErrorMessage` (session-reset hint).
      // Anything else is either a bug or an attacker-crafted envelope
      // trying to inject unauthenticated content, and must be rejected.
      const decodedContent = Content.decode(inner);
      const dem = decodedContent.decryptionErrorMessage;
      const hasOther =
        decodedContent.dataMessage != null ||
        decodedContent.syncMessage != null ||
        decodedContent.callMessage != null ||
        decodedContent.nullMessage != null ||
        decodedContent.receiptMessage != null ||
        decodedContent.typingMessage != null ||
        decodedContent.storyMessage != null ||
        decodedContent.editMessage != null;
      if (hasOther || dem == null || dem.length === 0) {
        throw new Error(
          "PLAINTEXT_CONTENT envelope contained disallowed fields " +
            "(only decryptionErrorMessage is permitted in plaintext)",
        );
      }
      return {
        envelope,
        plaintext: null,
        wasEncrypted: false,
        decryptionErrorMessage: dem,
      };
    }

    case EnvelopeType.DOUBLE_RATCHET: {
      if (!content) throw new Error("DOUBLE_RATCHET envelope has no body");
      if (!envelope.sourceServiceId || !envelope.sourceDeviceId) {
        throw new Error("DOUBLE_RATCHET envelope missing sender info");
      }
      const msg = SignalMessage.deserialize(content);
      const padded = await signalDecrypt(
        msg,
        ProtocolAddress.new(envelope.sourceServiceId, envelope.sourceDeviceId),
        stores.session,
        stores.identity,
      );
      return { envelope, plaintext: unpad(padded), wasEncrypted: true };
    }

    case EnvelopeType.PREKEY_MESSAGE: {
      if (!content) throw new Error("PREKEY_MESSAGE envelope has no body");
      if (!envelope.sourceServiceId || !envelope.sourceDeviceId) {
        throw new Error("PREKEY_MESSAGE envelope missing sender info");
      }
      const msg = PreKeySignalMessage.deserialize(content);
      const padded = await signalDecryptPreKey(
        msg,
        ProtocolAddress.new(envelope.sourceServiceId, envelope.sourceDeviceId),
        ProtocolAddress.new(localAci, localDeviceId),
        stores.session,
        stores.identity,
        stores.preKey,
        stores.signedPreKey,
        stores.kyberPreKey,
      );
      return { envelope, plaintext: unpad(padded), wasEncrypted: true };
    }

    case EnvelopeType.UNIDENTIFIED_SENDER: {
      if (!content) {
        throw new Error("UNIDENTIFIED_SENDER envelope has no body");
      }
      // Try each published trust root; Signal currently rotates between two.
      const roots = trustRoots();
      let result: Awaited<
        ReturnType<typeof sealedSenderDecryptMessage>
      > | null = null;
      let lastErr: unknown;
      for (const root of roots) {
        try {
          result = await sealedSenderDecryptMessage(
            content,
            root,
            envelope.timestamp,
            /* localE164 */ null,
            localAci,
            localDeviceId,
            stores.session,
            stores.identity,
            stores.preKey,
            stores.signedPreKey,
            stores.kyberPreKey,
          );
          break;
        } catch (e) {
          lastErr = e;
          // Only retry on trust-root validation failure; other errors are fatal.
          const msg = e instanceof Error ? e.message : String(e);
          if (!msg.includes("trust root")) throw e;
        }
      }
      if (!result) throw lastErr ?? new Error("sealed sender decrypt failed");
      return {
        envelope,
        plaintext: unpad(result.message()),
        wasEncrypted: true,
        sealedSender: {
          senderUuid: result.senderUuid(),
          senderDeviceId: result.deviceId(),
        },
      };
    }

    default:
      throw new Error(`Unknown envelope type: ${envelope.type}`);
  }
}
