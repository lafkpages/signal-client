// Outgoing message support: builds Content protos (DataMessage, sync Sent
// transcripts), encrypts per-device using our protocol stores, and drives
// the PUT /v1/messages flow with retry on mismatched-device errors.
//
// The low-level building blocks (prekey bundle fetch, session install,
// per-device encrypt, PUT /v1/messages) live in `sync.ts`; this file just
// glues them into user-facing helpers.

import type { signalservice } from "../protos/generated";
import type { IDataMessage } from "./protos.ts";
import type { ProtocolStores } from "./stores.ts";
import type { OutgoingMessage, SendMessagesOptions } from "./sync.ts";

import { Net, ProtocolAddress } from "@signalapp/libsignal-client";

import { Content, DataMessage, SyncMessage } from "./protos.ts";
import {
  DeviceMismatchError,
  encryptContentForDevice,
  getKeysForServiceId,
  installSessionFromDevice,
  randomPadding,
  sendMessages,
} from "./sync.ts";

// ---------- Content builders ----------

function encodeContent(content: {
  dataMessage?: signalservice.DataMessage;
  syncMessage?: signalservice.SyncMessage;
}) {
  const msg = Content.create(content);
  const out = Content.encode(msg).finish();
  const copy = new Uint8Array(out.byteLength);
  copy.set(out);
  return copy;
}

export interface DataMessageBuildOptions {
  /** Text body. Optional — Signal allows attachment-only / reaction-only msgs. */
  body?: string;
  /** Outgoing timestamp; must match the envelope timestamp at send time. */
  timestamp: number;
  /** Disappearing-message timer in seconds. Omitted when undefined. */
  expireTimer?: number;
  /**
   * expireTimer version. Signal bumps this monotonically per-conversation
   * whenever the timer changes. Omitted when undefined.
   */
  expireTimerVersion?: number;
  /** Our profile key, to allow the recipient to download our profile. */
  profileKey?: Uint8Array;
}

/** Build a protobufjs `IDataMessage` object from our user-facing options. */
export function buildDataMessage(opts: DataMessageBuildOptions): IDataMessage {
  return {
    timestamp: opts.timestamp,
    ...(opts.body !== undefined && { body: opts.body }),
    ...(opts.expireTimer !== undefined && { expireTimer: opts.expireTimer }),
    ...(opts.expireTimerVersion !== undefined && {
      expireTimerVersion: opts.expireTimerVersion,
    }),
    ...(opts.profileKey !== undefined && { profileKey: opts.profileKey }),
  };
}

/**
 * Builds a serialized `Content` proto containing a single `DataMessage`, ready
 * to hand to {@link sendContentToServiceId}.
 */
export function buildDataMessageContent(opts: DataMessageBuildOptions) {
  const dataMessage = DataMessage.create(buildDataMessage(opts));
  return encodeContent({ dataMessage });
}

export interface SyncSentTranscriptOptions {
  /** The DataMessage that was sent to the real recipient. */
  dataMessage: IDataMessage;
  /** Sent timestamp (must match the one used in the DataMessage). */
  timestamp: number;
  /** Service ID the message was sent to, if any. */
  destinationServiceId?: string;
  /** Optional E.164 phone number destination. */
  destinationE164?: string;
}

/**
 * Builds a serialized `Content` proto containing a `SyncMessage.Sent`
 * transcript for our other devices, so they know we sent a message to a peer.
 */
export function buildSyncSentTranscriptContent(
  opts: SyncSentTranscriptOptions,
) {
  const sent = SyncMessage.Sent.create({
    timestamp: opts.timestamp,
    message: DataMessage.create(opts.dataMessage),
    isRecipientUpdate: false,
    ...(opts.destinationServiceId !== undefined && {
      destinationServiceId: opts.destinationServiceId,
    }),
    ...(opts.destinationE164 !== undefined && {
      destinationE164: opts.destinationE164,
    }),
  });

  const syncMessage = SyncMessage.create({
    sent,
    padding: randomPadding(),
  });

  return encodeContent({ syncMessage });
}

// ---------- Send to a serviceId (all devices) ----------

export interface SendContentOptions extends SendMessagesOptions {
  /**
   * Devices to explicitly skip (e.g. our own deviceId when sending a sync
   * transcript to ourselves). Rare — Signal-Desktop does not skip devices.
   */
  skipDeviceIds?: number[];
  /** How many times to retry on 409/410 before giving up. Default: 3. */
  maxRetries?: number;
  /**
   * If true, we return silently when the resolved recipient-device list is
   * empty after applying `skipDeviceIds`. Used by the sync-transcript send
   * so a single-device account doesn't produce a wasted PUT.
   * Default: true.
   */
  skipIfNoRecipients?: boolean;
}

/**
 * Send an encoded `Content` proto to every active device on `serviceId`.
 *
 * If we already have sessions for this `serviceId` in the store we use those
 * device ids directly (no `GET /v2/keys` round-trip); 409 / 410 from
 * `PUT /v1/messages` teach us about new / stale devices via a refetch.
 */
export async function sendContentToServiceId(
  chat: Net.AuthenticatedChatConnection,
  stores: ProtocolStores,
  localAci: string,
  localDeviceId: number,
  serviceId: string,
  content: Uint8Array<ArrayBuffer>,
  opts: SendContentOptions,
  userAgent: string,
) {
  const localAddress = ProtocolAddress.new(localAci, localDeviceId);
  const maxRetries = opts.maxRetries ?? 3;
  const skipIfNoRecipients = opts.skipIfNoRecipients ?? true;
  const skip = new Set(opts.skipDeviceIds ?? []);

  let addresses: ProtocolAddress[] | null = null;

  // Device ids we must (re)install before encrypting, because their session
  // either never existed or just got archived/dropped by a 409/410 retry.
  let forceInstall = new Set<number>();
  let attempt = 0;

  while (true) {
    attempt++;

    if (!addresses) {
      const cachedIds = stores.session
        .listDeviceIds(serviceId)
        .filter((id) => !skip.has(id));

      // Fetch a bundle if we have no cached sessions, or if the previous
      // attempt flagged specific devices as needing a new session. On first
      // attempt with cached sessions we skip the fetch entirely.
      const needFetch = cachedIds.length === 0 || forceInstall.size > 0;

      if (needFetch) {
        const keys = await getKeysForServiceId(chat, serviceId, userAgent);
        addresses = [];

        for (const dev of keys.devices) {
          if (skip.has(dev.deviceId)) continue;

          const addr = ProtocolAddress.new(serviceId, dev.deviceId);
          const existing = await stores.session.getSession(addr);
          const needsInstall =
            !existing ||
            forceInstall.has(dev.deviceId) ||
            !existing.hasCurrentState(new Date());

          if (needsInstall) {
            await installSessionFromDevice(stores, addr, keys.identityKey, dev);
          }
          addresses.push(addr);
        }

        forceInstall = new Set();
      } else {
        addresses = cachedIds.map((id) => ProtocolAddress.new(serviceId, id));
      }
    }

    if (addresses.length === 0) {
      if (skipIfNoRecipients) return;

      throw new Error(
        `No devices to send to for ${serviceId} (all skipped or absent)`,
      );
    }

    const messages: OutgoingMessage[] = [];
    for (const addr of addresses) {
      messages.push(
        await encryptContentForDevice(stores, addr, localAddress, content),
      );
    }

    // TODO: test this (409 / 410 retry path — needs a mock chat connection)
    try {
      await sendMessages(chat, serviceId, messages, opts, userAgent);
      return;
    } catch (e) {
      if (!(e instanceof DeviceMismatchError) || attempt >= maxRetries) {
        throw e;
      }

      // Defense in depth: if the server reports a mismatch but all three
      // device lists are empty, we have no signal to act on and retrying
      // would just replay the same state until maxRetries. Bail out.
      if (
        e.extraDevices.length === 0 &&
        e.missingDevices.length === 0 &&
        e.staleDevices.length === 0
      ) {
        throw e;
      }

      if (e.status === 409) {
        console.debug(
          `sendContentToServiceId: 409 for ${serviceId} (attempt ${attempt}/${maxRetries}) extra=[${e.extraDevices.join(",")}] missing=[${e.missingDevices.join(",")}]`,
        );

        for (const id of e.extraDevices) {
          stores.session.deleteSession(ProtocolAddress.new(serviceId, id));
        }

        // `missingDevices` tells us which devices we forgot — they need a
        // fresh bundle install next round.
        for (const id of e.missingDevices) forceInstall.add(id);
      } else {
        console.debug(
          `sendContentToServiceId: 410 for ${serviceId} (attempt ${attempt}/${maxRetries}) stale=[${e.staleDevices.join(",")}]`,
        );

        // 410: stale sessions. Archive them and force-reinstall from a
        // fresh bundle before retrying.
        for (const id of e.staleDevices) {
          await stores.session.archiveSession(
            ProtocolAddress.new(serviceId, id),
          );
          forceInstall.add(id);
        }
      }

      // Refetch keys + rebuild addresses for the retry.
      addresses = null;
    }
  }
}
