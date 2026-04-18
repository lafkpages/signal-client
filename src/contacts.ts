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

export type ParsedContact = {
  aci?: string | undefined;
  aciBinary?: Uint8Array | undefined;
  number?: string | undefined;
  name?: string | undefined;
  expireTimer?: number | undefined;
  expireTimerVersion?: number | undefined;
  inboxPosition?: number | undefined;
  avatar?:
    | {
        contentType?: string | undefined;
        bytes: Uint8Array;
      }
    | undefined;
};

function readVarint(buf: Uint8Array, offset: number): [number, number] {
  let result = 0;
  let shift = 0;
  let i = offset;
  while (i < buf.length) {
    const b = buf[i++]!;
    result |= (b & 0x7f) << shift;
    if ((b & 0x80) === 0) {
      return [result >>> 0, i - offset];
    }
    shift += 7;
    if (shift > 35) throw new Error("Varint too long");
  }
  throw new Error("Truncated varint");
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

    out.push({
      aci: decoded.aci ?? undefined,
      aciBinary: decoded.aciBinary ?? undefined,
      number: decoded.number ?? undefined,
      name: decoded.name ?? undefined,
      expireTimer: decoded.expireTimer ?? undefined,
      expireTimerVersion: decoded.expireTimerVersion ?? undefined,
      inboxPosition: decoded.inboxPosition ?? undefined,
      avatar: avatarBytes
        ? {
            contentType: decoded.avatar?.contentType ?? undefined,
            bytes: avatarBytes,
          }
        : undefined,
    });
  }
  return out;
}
