import type { LinkDeviceRequest } from "./chatApi.ts";
import type { IContent } from "./protos.ts";
import type { ProvisionDecryptResult } from "./provisioningCipher.ts";
import type { DataMessageBuildOptions } from "./send.ts";
import type { KeyIdCounters, LinkedState } from "./state.ts";
import type { ProtocolStores } from "./stores.ts";

import { Net } from "@signalapp/libsignal-client";

import { version } from "../package.json";
import {
  connectAuthedChat,
  generateAccountPassword,
  generateOneTimePreKeys,
  generatePreKeys,
  linkDevice,
  randomRegistrationId,
  registerOneTimeKeys,
} from "./chatApi.ts";
import { getOrCreateMasterKey } from "./crypto.ts";
import { decryptEnvelope, parseEnvelope } from "./decrypt.ts";
import { encryptDeviceName } from "./deviceName.ts";
import { Content } from "./protos.ts";
import { ProvisioningCipher } from "./provisioningCipher.ts";
import {
  buildDataMessage,
  buildDataMessageContent,
  buildSyncSentTranscriptContent,
  sendContentToServiceId,
} from "./send.ts";
import {
  b64,
  loadPrivateKey,
  loadState,
  randomInitialKeyId,
  saveState,
  wrappingAdd24Nonzero,
} from "./state.ts";
import { createStores } from "./stores.ts";
import { sendSyncRequests } from "./sync.ts";

// ---------- Public types ----------

export interface SignalClientConfig {
  /** User-Agent string sent on all HTTP/WS requests.
   * @default `@luisafk/signal-client v${version}`
   */
  userAgent?: string;

  /** Device name, encrypted and registered with the server on link. */
  readonly deviceName: string;

  /** Path to the JSON file holding linked-account state. */
  readonly stateFile: string;

  /** Directory holding sessions / identities / pre-keys (one JSON per kind). */
  readonly storeDir: string;

  /** libsignal Net environment. Defaults to Production. */
  readonly env?: Net.Environment;
}

export type IncomingMessage = {
  /** Service ID of the sender (sealed-sender unwrapped if applicable). */
  senderServiceId: string;
  senderDeviceId: number;
  /** Server-provided envelope timestamp. */
  timestamp: number;
  /** Outer envelope type (Envelope.Type enum). */
  envelopeType: number;
  /** Decoded inner Content proto, or null if it failed to decode. */
  content: IContent | null;
  /** Raw plaintext bytes (post-padding-strip), or null for receipts. */
  plaintext: Uint8Array | null;
  /** True if delivered via sealed sender. */
  sealedSender: boolean;
};

export type SignalClientEvents = {
  /** Successfully decrypted envelope with non-empty plaintext. */
  message: (msg: IncomingMessage) => void;
  /** Server-side delivery receipt (envelope type 5). */
  serverReceipt: (envelope: {
    timestamp: number;
    sourceServiceId?: string | undefined;
    sourceDeviceId?: number | undefined;
  }) => void;
  /** Decryption failed; outerType is the envelope type if parseable. */
  decryptError: (err: unknown, outerType: number | null) => void;
  /**
   * Peer sent a `DecryptionErrorMessage` in a PLAINTEXT_CONTENT envelope,
   * signaling that our end of the ratchet is broken and they want us to
   * reset the session. The bytes are the raw serialized
   * `DecryptionErrorMessage`. Unauthenticated — treat only as a hint.
   */
  peerDecryptionError: (info: {
    senderServiceId: string;
    senderDeviceId: number;
    timestamp: number;
    decryptionErrorMessage: Uint8Array;
  }) => void;
  /** Server reports the queue of pending messages is drained. */
  queueEmpty: () => void;
  /** Authenticated chat connection was interrupted. */
  interrupted: (err: Error | null) => void;
  /** Server-side alerts pushed on the auth socket. */
  alerts: (alerts: string[]) => void;
};

type Listener<E extends keyof SignalClientEvents> = SignalClientEvents[E];

// ---------- Helpers ----------

function decodeContent(plaintext: Uint8Array): IContent | null {
  try {
    const msg = Content.decode(plaintext);
    return Content.toObject(msg, { longs: Number, defaults: false });
  } catch {
    return null;
  }
}

function buildQrUrl(
  address: string,
  publicKey: Uint8Array,
  capabilities: string[],
): string {
  const pub = Buffer.from(publicKey).toString("base64");
  const params = new URLSearchParams({
    uuid: address,
    pub_key: pub,
    capabilities: capabilities.join(","),
  });
  return `sgnl://linkdevice?${params.toString()}`;
}

async function awaitProvisioningEnvelope(
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

// ---------- SignalClient ----------

/**
 * High-level wrapper around the libsignal chat / provisioning APIs.
 *
 * Usage:
 *   const client = new SignalClient(cfg);
 *   if (!client.isLinked()) await client.link({ onQrUrl: console.log });
 *   client.on("message", (m) => ...);
 *   await client.connect();
 *
 * The class is intentionally small: it owns the state file, the protocol
 * stores, and the authenticated chat connection. Higher-level concerns
 * (QR rendering, contact-attachment download, message dispatch) live in
 * the caller.
 */
export class SignalClient {
  readonly config: Required<SignalClientConfig>;
  readonly net: Net.Net;

  private state: LinkedState | undefined;
  private stores: ProtocolStores | undefined;
  private authChat: Net.AuthenticatedChatConnection | undefined;
  private masterKey: Uint8Array | undefined;

  private readonly listeners: {
    [K in keyof SignalClientEvents]: Set<Listener<K>>;
  } = {
    message: new Set(),
    serverReceipt: new Set(),
    decryptError: new Set(),
    peerDecryptionError: new Set(),
    queueEmpty: new Set(),
    interrupted: new Set(),
    alerts: new Set(),
  };

  constructor(config: SignalClientConfig) {
    this.config = {
      userAgent: `@luisafk/signal-client v${version}`,
      env: Net.Environment.Production,
      ...config,
    };

    this.net = new Net.Net({
      env: this.config.env,
      userAgent: this.config.userAgent,
    });
  }

  /**
   * Loads the master encryption key from the OS credential store (creating
   * one on first use) and reads any existing persisted state + protocol
   * stores from disk. Must be called once before {@link isLinked},
   * {@link link}, or {@link connect}.
   */
  async init(): Promise<void> {
    if (this.masterKey) return;
    this.masterKey = await getOrCreateMasterKey();

    this.state = loadState(this.config.stateFile, this.masterKey);

    if (this.state) {
      const identityPrivate = loadPrivateKey(this.state.aciIdentityPrivate);
      this.stores = createStores(
        identityPrivate,
        this.state.registrationId,
        this.masterKey,
        this.config.storeDir,
      );

      // State files written before key-id counters were introduced won't
      // have `keyIds`. Seed the counters from what's already in the store
      // (ACI side) / random (PNI side) so future key generations can't
      // collide with existing entries, and persist immediately.
      if (!this.state.keyIds) {
        this.state.keyIds = {
          preKeyIdAci: wrappingAdd24Nonzero(this.stores.preKey.maxKeyId(), 1),
          signedPreKeyIdAci: wrappingAdd24Nonzero(
            this.stores.signedPreKey.maxKeyId(),
            1,
          ),
          kyberPreKeyIdAci: wrappingAdd24Nonzero(
            this.stores.kyberPreKey.maxKeyId(),
            1,
          ),
          preKeyIdPni: randomInitialKeyId(),
          signedPreKeyIdPni: randomInitialKeyId(),
          kyberPreKeyIdPni: randomInitialKeyId(),
        };
        saveState(this.config.stateFile, this.state, this.masterKey);
      }
    }
  }

  private requireMasterKey(): Uint8Array {
    if (!this.masterKey) {
      throw new Error("SignalClient.init() must be called before use");
    }
    return this.masterKey;
  }

  // ---- Accessors ----

  isLinked(): boolean {
    this.requireMasterKey();
    return this.state !== undefined;
  }

  /** Throws if not linked yet. */
  get linkedState(): LinkedState {
    if (!this.state) throw new Error("SignalClient is not linked");
    return this.state;
  }

  get aci(): string {
    return this.linkedState.aci;
  }

  get deviceId(): number {
    return this.linkedState.deviceId;
  }

  get protocolStores(): ProtocolStores {
    if (!this.stores) throw new Error("SignalClient is not linked");
    return this.stores;
  }

  // ---- Event subscription ----

  on<E extends keyof SignalClientEvents>(
    event: E,
    listener: Listener<E>,
  ): () => void {
    this.listeners[event].add(listener);
    return () => this.off(event, listener);
  }

  off<E extends keyof SignalClientEvents>(
    event: E,
    listener: Listener<E>,
  ): void {
    this.listeners[event].delete(listener);
  }

  private emit<E extends keyof SignalClientEvents>(
    event: E,
    ...args: Parameters<Listener<E>>
  ): void {
    for (const l of this.listeners[event]) {
      try {
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        (l as (...a: any[]) => void)(...args);
      } catch (e) {
        console.error(`SignalClient listener for "${event}" threw:`, e);
      }
    }
  }

  // ---- Linking ----

  /**
   * Runs the QR provisioning flow and registers a new linked device.
   * On success, persists state to `stateFile` and sets up protocol stores.
   * Throws if the client is already linked.
   */
  async link(opts: {
    onQrUrl: (url: string) => void;
    /** Number of one-time EC + Kyber pre-keys to upload per identity. */
    oneTimePreKeyCount?: number;
  }): Promise<LinkedState> {
    const masterKey = this.requireMasterKey();
    if (this.state) throw new Error("Already linked");

    const cipher = new ProvisioningCipher();
    const msg = await awaitProvisioningEnvelope(this.net, cipher, opts.onQrUrl);

    if (!msg.number) throw new Error("ProvisionMessage missing number");
    if (!msg.provisioningCode)
      throw new Error("ProvisionMessage missing provisioningCode");
    if (!msg.pniKeyPair)
      throw new Error("ProvisionMessage missing pni identity key");

    const password = generateAccountPassword();
    const registrationId = randomRegistrationId();
    const pniRegistrationId = randomRegistrationId();

    // Initialize monotonic key-id counters (Signal-Desktop style). Each
    // identity × key-kind gets its own 24-bit counter; on first use the
    // starting id is random, and every subsequent allocation increments it
    // via `wrappingAdd24`. This replaces the per-key random id generation
    // that could otherwise collide with existing entries in our stores.
    const keyIds: KeyIdCounters = {
      preKeyIdAci: randomInitialKeyId(),
      preKeyIdPni: randomInitialKeyId(),
      signedPreKeyIdAci: randomInitialKeyId(),
      signedPreKeyIdPni: randomInitialKeyId(),
      kyberPreKeyIdAci: randomInitialKeyId(),
      kyberPreKeyIdPni: randomInitialKeyId(),
    };

    const aciSignedPreKeyId = keyIds.signedPreKeyIdAci;
    keyIds.signedPreKeyIdAci = wrappingAdd24Nonzero(aciSignedPreKeyId, 1);
    const pniSignedPreKeyId = keyIds.signedPreKeyIdPni;
    keyIds.signedPreKeyIdPni = wrappingAdd24Nonzero(pniSignedPreKeyId, 1);

    const aciPqLastResortPreKeyId = keyIds.kyberPreKeyIdAci;
    keyIds.kyberPreKeyIdAci = wrappingAdd24Nonzero(aciPqLastResortPreKeyId, 1);
    const pniPqLastResortPreKeyId = keyIds.kyberPreKeyIdPni;
    keyIds.kyberPreKeyIdPni = wrappingAdd24Nonzero(pniPqLastResortPreKeyId, 1);

    const aciKeys = generatePreKeys(msg.aciKeyPair, {
      signedPreKeyId: aciSignedPreKeyId,
      pqLastResortPreKeyId: aciPqLastResortPreKeyId,
    });
    const pniKeys = generatePreKeys(msg.pniKeyPair, {
      signedPreKeyId: pniSignedPreKeyId,
      pqLastResortPreKeyId: pniPqLastResortPreKeyId,
    });

    const encryptedName = encryptDeviceName(
      this.config.deviceName,
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

    const result = await linkDevice(
      this.net,
      msg.number,
      password,
      body,
      this.config.userAgent,
    );

    // Build stores immediately so we can persist pre-key private halves
    // alongside the upload below.
    const stores = createStores(
      msg.aciKeyPair.privateKey,
      registrationId,
      masterKey,
      this.config.storeDir,
    );
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

    const count = opts.oneTimePreKeyCount ?? 100;

    const aciOneTimeStart = {
      startPreKeyId: keyIds.preKeyIdAci,
      startKyberPreKeyId: keyIds.kyberPreKeyIdAci,
    };
    keyIds.preKeyIdAci = wrappingAdd24Nonzero(
      aciOneTimeStart.startPreKeyId,
      count,
    );
    keyIds.kyberPreKeyIdAci = wrappingAdd24Nonzero(
      aciOneTimeStart.startKyberPreKeyId,
      count,
    );
    const pniOneTimeStart = {
      startPreKeyId: keyIds.preKeyIdPni,
      startKyberPreKeyId: keyIds.kyberPreKeyIdPni,
    };
    keyIds.preKeyIdPni = wrappingAdd24Nonzero(
      pniOneTimeStart.startPreKeyId,
      count,
    );
    keyIds.kyberPreKeyIdPni = wrappingAdd24Nonzero(
      pniOneTimeStart.startKyberPreKeyId,
      count,
    );

    const aciOneTime = generateOneTimePreKeys(
      msg.aciKeyPair,
      aciOneTimeStart,
      count,
    );
    const pniOneTime = generateOneTimePreKeys(
      msg.pniKeyPair,
      pniOneTimeStart,
      count,
    );

    for (const k of aciOneTime.preKeyPrivates) {
      stores.preKey.add(k.keyId, k.privateKey);
    }
    for (const k of aciOneTime.pqPreKeyPrivates) {
      // One-time Kyber pre-key signatures are only needed sender-side.
      stores.kyberPreKey.add(k.keyId, Date.now(), k.keyPair, new Uint8Array());
    }

    // We need an authenticated chat to upload one-time pre-keys. Open it
    // *without* registering our incoming-message handler — the connect()
    // method will reopen with the handler attached.
    const tempChat = await connectAuthedChat(
      this.net,
      result.uuid,
      result.deviceId,
      password,
      () => {
        /* drop incoming until connect() is called */
      },
    );
    try {
      await registerOneTimeKeys(
        tempChat,
        "aci",
        { preKeys: aciOneTime.preKeys, pqPreKeys: aciOneTime.pqPreKeys },
        this.config.userAgent,
      );
      await registerOneTimeKeys(
        tempChat,
        "pni",
        { preKeys: pniOneTime.preKeys, pqPreKeys: pniOneTime.pqPreKeys },
        this.config.userAgent,
      );
    } finally {
      await tempChat.disconnect();
    }

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

      keyIds,
    };
    saveState(this.config.stateFile, state, masterKey);

    this.state = state;
    this.stores = stores;
    return state;
  }

  /** Raw ProvisionMessage from the most recent successful link, if any. */
  // (We deliberately don't keep this — callers should rely on `linkedState`
  // and the on-disk store for everything we need post-link.)

  // ---- Authenticated connection ----

  /**
   * Opens the authenticated chat connection and starts dispatching incoming
   * envelopes via events. Idempotent: returns immediately if already
   * connected. Throws if the client is not linked.
   */
  async connect(): Promise<void> {
    if (this.authChat) return;
    if (!this.state || !this.stores) {
      throw new Error("connect() called before link()");
    }
    const { aci, deviceId, password } = this.state;

    this.authChat = await this.net.connectAuthenticatedChat(
      `${aci}.${deviceId}`,
      password,
      /* receiveStories */ false,
      {
        onConnectionInterrupted: (err) => {
          this.emit("interrupted", err ?? null);
        },
        onIncomingMessage: (envelope, _timestamp, ack) => {
          // Decrypt asynchronously, but ack only after we've at least
          // attempted decryption — so a flaky listener doesn't cause us to
          // permanently lose the envelope.
          void this.handleIncoming(envelope).finally(() => {
            ack.send(200);
          });
        },
        onQueueEmpty: () => this.emit("queueEmpty"),
        onReceivedAlerts: (alerts) => {
          if (alerts.length > 0) this.emit("alerts", alerts);
        },
      },
    );
  }

  /** Closes the authenticated chat connection if open. */
  async disconnect(): Promise<void> {
    const chat = this.authChat;
    this.authChat = undefined;
    if (chat) await chat.disconnect();
  }

  /** Returns the underlying authenticated chat connection (must be connected). */
  get chat(): Net.AuthenticatedChatConnection {
    if (!this.authChat) throw new Error("SignalClient is not connected");
    return this.authChat;
  }

  // ---- Sync helpers ----

  /**
   * Sends SyncMessage.Request for CONTACTS / CONFIGURATION / BLOCKED to
   * every other device on this account. Replies arrive as `message` events.
   */
  async requestSync(): Promise<void> {
    await sendSyncRequests(
      this.chat,
      this.protocolStores,
      this.aci,
      this.deviceId,
      this.config.userAgent,
    );
  }

  // ---- Sending ----

  /**
   * Sends a DataMessage to `destinationServiceId` (ACI or PNI) and, unless
   * disabled, also sends a `SyncMessage.Sent` transcript to our own other
   * devices so they mirror the send.
   *
   * Returns the sent timestamp — callers should surface this as the message
   * id / delivery-receipt key.
   */
  async sendMessage(
    destinationServiceId: string,
    opts: Omit<DataMessageBuildOptions, "timestamp"> & {
      /** Override the sent timestamp. Defaults to `Date.now()`. */
      timestamp?: number;
      /** Urgent flag on the outer envelope. Default: true. */
      urgent?: boolean;
      /**
       * Set to false to skip the sync-sent transcript. Default: true.
       * When true, a transcript is only actually sent if we have at least
       * one other linked device.
       */
      sendSyncTranscriptIfNecessary?: boolean;
      /** Destination E.164 to stamp on the sync transcript, if any. */
      destinationE164?: string;
    } = {},
  ): Promise<{ timestamp: number }> {
    const { aci, deviceId } = this.linkedState;
    const stores = this.protocolStores;
    const timestamp = opts.timestamp ?? Date.now();

    const dataBuildOpts: DataMessageBuildOptions = {
      timestamp,
      ...(opts.body !== undefined && { body: opts.body }),
      ...(opts.expireTimer !== undefined && { expireTimer: opts.expireTimer }),
      ...(opts.expireTimerVersion !== undefined && {
        expireTimerVersion: opts.expireTimerVersion,
      }),
      ...(opts.profileKey !== undefined && { profileKey: opts.profileKey }),
    };
    const dataMessage = buildDataMessage(dataBuildOpts);
    const dataContent = buildDataMessageContent(dataBuildOpts);

    await sendContentToServiceId(
      this.chat,
      stores,
      aci,
      deviceId,
      destinationServiceId,
      dataContent,
      { timestamp, urgent: opts.urgent ?? true },
      this.config.userAgent,
    );

    if (opts.sendSyncTranscriptIfNecessary !== false) {
      const transcript = buildSyncSentTranscriptContent({
        dataMessage,
        timestamp,
        destinationServiceId,
        ...(opts.destinationE164 !== undefined && {
          destinationE164: opts.destinationE164,
        }),
      });

      try {
        await sendContentToServiceId(
          this.chat,
          stores,
          aci,
          deviceId,
          aci,
          transcript,
          {
            timestamp,
            urgent: false,
            // Don't send the transcript to ourselves.
            skipDeviceIds: [deviceId],
          },
          this.config.userAgent,
        );
      } catch (e) {
        // A failed sync transcript shouldn't fail the primary send.
        console.warn("sendMessage: sync transcript failed:", e);
      }
    }

    return { timestamp };
  }

  // ---- Internals ----

  private async handleIncoming(envelopeBytes: Uint8Array): Promise<void> {
    const stores = this.stores;
    if (!stores) return; // shouldn't happen post-link
    try {
      const result = await decryptEnvelope(
        envelopeBytes,
        stores,
        this.aci,
        this.deviceId,
      );
      if (result.decryptionErrorMessage) {
        // PLAINTEXT_CONTENT: unauthenticated ratchet-reset hint. Must NOT
        // be surfaced through the regular `message` path.
        this.emit("peerDecryptionError", {
          senderServiceId: result.envelope.sourceServiceId ?? "",
          senderDeviceId: result.envelope.sourceDeviceId ?? 0,
          timestamp: result.envelope.timestamp,
          decryptionErrorMessage: result.decryptionErrorMessage,
        });
        return;
      }
      if (!result.plaintext) {
        // Server delivery receipts have no plaintext.
        this.emit("serverReceipt", {
          timestamp: result.envelope.timestamp,
          sourceServiceId: result.envelope.sourceServiceId,
          sourceDeviceId: result.envelope.sourceDeviceId,
        });
        return;
      }
      const senderServiceId =
        result.sealedSender?.senderUuid ??
        result.envelope.sourceServiceId ??
        "";
      const senderDeviceId =
        result.sealedSender?.senderDeviceId ??
        result.envelope.sourceDeviceId ??
        0;
      this.emit("message", {
        senderServiceId,
        senderDeviceId,
        timestamp: result.envelope.timestamp,
        envelopeType: result.envelope.type,
        content: decodeContent(result.plaintext),
        plaintext: result.plaintext,
        sealedSender: result.sealedSender !== undefined,
      });
    } catch (e) {
      let outerType: number | null = null;
      try {
        outerType = parseEnvelope(envelopeBytes).type;
      } catch {
        /* ignore */
      }
      this.emit("decryptError", e, outerType);
    }
  }
}
