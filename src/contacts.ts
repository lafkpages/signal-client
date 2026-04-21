// Parse the plaintext from a decrypted SyncMessage.Contacts attachment.
//
// Wire format (see Signal-Android `DeviceContactsInputStream`):
//
//   repeat until EOF:
//     varint length
//     ContactDetails bytes[length]
//     if contactDetails.avatar.length > 0:
//       avatarBytes[contactDetails.avatar.length]   // raw image bytes

import { ContactDetails } from "./protos.ts";

export interface ParsedContact {
  aci: string | null;
  aciBinary: Uint8Array | null;
  number: string | null;
  name: string | null;
  expireTimer: number | null;
  expireTimerVersion: number | null;
  inboxPosition: number | null;
  avatar: {
    contentType?: string | null;
    bytes: Uint8Array;
  } | null;
}

function readVarint(buf: Uint8Array, offset: number): [number, number] {
  // JS bitwise ops are signed 32-bit and shift counts are mod 32, so we
  // accumulate in BigInt to avoid sign-extension and silent wrap-around.
  let result = 0n;
  let shift = 0n;
  let i = offset;
  // Protobuf varints are at most 10 bytes (64-bit).
  const end = Math.min(buf.length, i + 10);
  while (i < end) {
    const b = buf[i++]!;
    result |= BigInt(b & 0x7f) << shift;
    if ((b & 0x80) === 0) {
      if (result > Number.MAX_SAFE_INTEGER) {
        throw new Error("Varint exceeds MAX_SAFE_INTEGER");
      }
      return [Number(result), i - offset];
    }
    shift += 7n;
  }
  if (i === buf.length) throw new Error("Truncated varint");
  throw new Error("Varint too long");
}

export function parseContactDetailsStream(bytes: Uint8Array): ParsedContact[] {
  const out: ParsedContact[] = [];
  let pos = 0;
  while (pos < bytes.length) {
    const [len, consumed] = readVarint(bytes, pos);
    pos += consumed;
    if (pos + len > bytes.length) {
      throw new Error(
        `ContactDetails length ${len} exceeds remaining ${bytes.length - pos}`,
      );
    }
    const slice = bytes.subarray(pos, pos + len);
    pos += len;

    const decoded = ContactDetails.decode(slice);

    const avatarLen = decoded.avatar?.length ?? 0;
    let avatarBytes: Uint8Array | undefined;
    if (avatarLen > 0) {
      if (pos + avatarLen > bytes.length) {
        throw new Error(
          `Avatar length ${avatarLen} exceeds remaining ${bytes.length - pos}`,
        );
      }
      avatarBytes = bytes.subarray(pos, pos + avatarLen);
      pos += avatarLen;
    }

    // protobuf.js decodes unset proto2 `optional string` fields as "" rather
    // than leaving them undefined, and unset `bytes` fields as zero-length
    // buffers. Normalise both so callers can rely on `??` falling through.
    const aci = decoded.aci || null;
    const aciBinary =
      decoded.aciBinary && decoded.aciBinary.length > 0
        ? decoded.aciBinary
        : null;

    out.push({
      aci,
      aciBinary,
      number: decoded.number || null,
      name: decoded.name || null,
      expireTimer: decoded.expireTimer ?? null,
      expireTimerVersion: decoded.expireTimerVersion ?? null,
      inboxPosition: decoded.inboxPosition ?? null,
      avatar: avatarBytes
        ? {
            contentType: decoded.avatar?.contentType || null,
            bytes: avatarBytes,
          }
        : null,
    });
  }
  return out;
}
