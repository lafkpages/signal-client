// Attachment download + decryption.
//
// Signal attachments are uploaded encrypted to a CDN. The download URL
// depends on `cdnNumber` and whether the pointer carries a `cdnId` (cdn 0)
// or `cdnKey` (cdn 2/3):
//
//   cdn 0:  https://cdn.signal.org/attachments/<cdnId-u64>
//   cdn 2:  https://cdn2.signal.org/attachments/<cdnKey>
//   cdn 3:  https://cdn3.signal.org/attachments/<cdnKey>
//
// The downloaded blob layout is:
//
//   [ IV (16) | ciphertext | HMAC-SHA256 tag (32) ]
//
// `key` in the AttachmentPointer is 64 bytes: AES-256 key || HMAC-SHA256 key.
// After verifying the HMAC and the pointer's `digest` (SHA-256 over the whole
// blob), the ciphertext is decrypted with AES-256-CBC + PKCS#7. Signal also
// zero-pads the plaintext to a bucket size, so the caller should truncate to
// `pointer.size` bytes.

import type Long from "long";

import {
  createDecipheriv,
  createHash,
  createHmac,
  timingSafeEqual,
} from "node:crypto";

import { SIGNAL_CA_PEM } from "./config";

// Structural superset of generated `signalservice.IAttachmentPointer` — accepts
// the same nullable fields plus a few extra shapes for cdnId (Long, bigint,
// string) that pop up depending on how the proto was decoded.
export interface AttachmentPointerLike {
  cdnId?: string | number | bigint | Long | null;
  cdnKey?: string | null;
  cdnNumber?: number | null;
  key?: Uint8Array | null;
  digest?: Uint8Array | null;
  size?: number | null;
  contentType?: string | null;
}

function cdnBaseUrl(cdnNumber: number | null | undefined) {
  switch (cdnNumber ?? 0) {
    case 0:
      return "https://cdn.signal.org";
    case 2:
      return "https://cdn2.signal.org";
    case 3:
      return "https://cdn3.signal.org";
    default:
      throw new Error(`Unsupported cdnNumber: ${cdnNumber}`);
  }
}

function pointerPath(ptr: AttachmentPointerLike) {
  if (ptr.cdnKey && ptr.cdnKey.length > 0) {
    return `/attachments/${ptr.cdnKey}`;
  }
  if (ptr.cdnId !== undefined && ptr.cdnId !== null) {
    return `/attachments/${ptr.cdnId.toString()}`;
  }
  throw new Error("AttachmentPointer has neither cdnKey nor cdnId");
}

/** Raw HTTPS GET of the encrypted attachment blob. */
export async function downloadAttachment(
  ptr: AttachmentPointerLike,
  userAgent: string,
) {
  const url = cdnBaseUrl(ptr.cdnNumber) + pointerPath(ptr);
  const res = await fetch(url, {
    method: "GET",
    headers: { "User-Agent": userAgent },
    tls: { ca: SIGNAL_CA_PEM },
  });

  if (!res.ok) {
    throw new Error(`Attachment GET ${url} failed: ${res.status}`);
  }

  return new Uint8Array(await res.arrayBuffer());
}

/**
 * Decrypts an encrypted attachment blob using the `key` and `digest` fields
 * from the AttachmentPointer. Returns the padded plaintext (truncate to
 * `ptr.size` to get the real payload).
 */
export function decryptAttachment(
  blob: Uint8Array,
  ptr: AttachmentPointerLike,
) {
  if (!ptr.key || ptr.key.length !== 64) {
    throw new Error("AttachmentPointer.key must be 64 bytes");
  }
  if (blob.length < 16 + 32 + 16) {
    throw new Error(`Attachment blob too short: ${blob.length}`);
  }

  if (ptr.digest && ptr.digest.length > 0) {
    const sha = createHash("sha256").update(blob).digest();
    if (
      sha.length !== ptr.digest.length ||
      !timingSafeEqual(sha, Buffer.from(ptr.digest))
    ) {
      throw new Error("Attachment digest mismatch");
    }
  }

  const aesKey = Buffer.from(ptr.key.subarray(0, 32));
  const macKey = Buffer.from(ptr.key.subarray(32, 64));
  const iv = blob.subarray(0, 16);
  const ct = blob.subarray(16, blob.length - 32);
  const mac = blob.subarray(blob.length - 32);

  const expected = createHmac("sha256", macKey).update(iv).update(ct).digest();
  if (!timingSafeEqual(expected, Buffer.from(mac))) {
    throw new Error("Attachment HMAC mismatch");
  }

  const decipher = createDecipheriv("aes-256-cbc", aesKey, Buffer.from(iv));
  const plaintext = Buffer.concat([
    decipher.update(Buffer.from(ct)),
    decipher.final(),
  ]);
  return new Uint8Array(plaintext);
}

/** Download + decrypt in one step. Truncates to `pointer.size` if set. */
export async function fetchAndDecryptAttachment(
  ptr: AttachmentPointerLike,
  userAgent: string,
) {
  const blob = await downloadAttachment(ptr, userAgent);
  const padded = decryptAttachment(blob, ptr);

  if (typeof ptr.size !== "number" || ptr.size < 0) {
    throw new Error("AttachmentPointer.size is required");
  }

  if (ptr.size > padded.length) {
    throw new Error(
      `AttachmentPointer.size (${ptr.size}) exceeds decrypted length (${padded.length})`,
    );
  }

  return padded.subarray(0, ptr.size);
}
