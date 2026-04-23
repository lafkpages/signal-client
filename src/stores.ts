// libsignal-client store implementations with optional file-backed
// persistence. Pass a directory path + encryption key to `createStores` to
// enable durability: every mutation writes the affected map to its encrypted
// `.enc` file atomically.
import type { Uuid } from "@signalapp/libsignal-client";

import {
  existsSync,
  mkdirSync,
  readFileSync,
  renameSync,
  writeFileSync,
} from "node:fs";
import { dirname, join } from "node:path";

import {
  Direction,
  IdentityChange,
  IdentityKeyStore,
  KEMKeyPair,
  KyberPreKeyRecord,
  KyberPreKeyStore,
  PreKeyRecord,
  PreKeyStore,
  PrivateKey,
  ProtocolAddress,
  PublicKey,
  SenderKeyRecord,
  SenderKeyStore,
  SessionRecord,
  SessionStore,
  SignedPreKeyRecord,
  SignedPreKeyStore,
} from "@signalapp/libsignal-client";

import { decryptBlob, encryptBlob } from "./crypto.ts";

function key(addr: ProtocolAddress): string {
  return `${addr.name()}.${addr.deviceId()}`;
}

// ---- Persisted byte-map primitive ------------------------------------------

class PersistedBytesMap {
  private readonly data = new Map<string, Uint8Array>();

  constructor(
    private readonly key: Uint8Array,
    private readonly path?: string,
  ) {
    if (!path || !existsSync(path)) return;

    try {
      const raw = readFileSync(path);
      const decrypted = decryptBlob(new Uint8Array(raw), key);
      const json = Buffer.from(decrypted).toString("utf8");
      const obj = JSON.parse(json) as Record<string, string>;

      for (const [k, v] of Object.entries(obj)) {
        this.data.set(k, Buffer.from(v, "base64"));
      }
    } catch (e) {
      console.warn(`Failed to load ${path}:`, e);
    }
  }

  get(k: string) {
    return this.data.get(k);
  }

  set(k: string, v: Uint8Array) {
    this.data.set(k, v);
    this.flush();
  }

  delete(k: string) {
    this.data.delete(k);
    this.flush();
  }

  /** Returns the largest numeric-looking key, or 0 if none. */
  maxNumericKey() {
    let max = 0;
    for (const k of this.data.keys()) {
      const n = Number(k);
      if (Number.isInteger(n) && n > max) max = n;
    }
    return max;
  }

  keys() {
    return this.data.keys();
  }

  private flush() {
    if (!this.path) return;

    const obj: Record<string, string> = {};
    for (const [k, v] of this.data) {
      obj[k] = Buffer.from(v).toString("base64");
    }
    mkdirSync(dirname(this.path), { recursive: true });
    const plaintext = Buffer.from(JSON.stringify(obj), "utf8");
    const envelope = encryptBlob(plaintext, this.key);
    const tmp = this.path + ".tmp";
    writeFileSync(tmp, envelope, { mode: 0o600 });
    renameSync(tmp, this.path);
  }
}

// ---- Store implementations -------------------------------------------------

export class InMemorySessionStore extends SessionStore {
  private readonly sessions: PersistedBytesMap;

  constructor(key: Uint8Array, path?: string) {
    super();
    this.sessions = new PersistedBytesMap(key, path);
  }

  async saveSession(name: ProtocolAddress, record: SessionRecord) {
    this.sessions.set(key(name), record.serialize());
  }

  async getSession(name: ProtocolAddress) {
    const raw = this.sessions.get(key(name));
    return raw ? SessionRecord.deserialize(Buffer.from(raw)) : null;
  }

  async getExistingSessions(addresses: ProtocolAddress[]) {
    const out: SessionRecord[] = [];
    for (const a of addresses) {
      const r = await this.getSession(a);
      if (!r) throw new Error(`No session for ${key(a)}`);
      out.push(r);
    }
    return out;
  }

  /**
   * Archives the current sender chain on the session at `address`, so the
   * next outbound message will force a fresh key agreement (PreKey message).
   * Matches Signal-Desktop's `archiveSession`, used on 410 stale-device
   * responses from `PUT /v1/messages`.
   */
  async archiveSession(address: ProtocolAddress) {
    const record = await this.getSession(address);
    if (!record) return;
    record.archiveCurrentState();
    this.sessions.set(key(address), record.serialize());
  }

  /** Removes a session entirely — used on 409 extra-device responses. */
  deleteSession(address: ProtocolAddress) {
    this.sessions.delete(key(address));
  }

  /** Archives every session whose address name matches `serviceId`. */
  async archiveAllSessions(serviceId: string) {
    const prefix = `${serviceId}.`;
    const matching: string[] = [];
    for (const k of this.sessions.keys()) {
      if (k.startsWith(prefix)) matching.push(k);
    }
    for (const k of matching) {
      const raw = this.sessions.get(k);
      if (!raw) continue;
      const record = SessionRecord.deserialize(Buffer.from(raw));
      record.archiveCurrentState();
      this.sessions.set(k, record.serialize());
    }
  }

  /**
   * Returns every deviceId for which we have a session under `serviceId`.
   * Used to avoid a `GET /v2/keys/<serviceId>/*` round-trip when we already
   * know the peer's active device list.
   */
  listDeviceIds(serviceId: string) {
    const prefix = `${serviceId}.`;
    const out: number[] = [];
    for (const k of this.sessions.keys()) {
      if (!k.startsWith(prefix)) continue;
      const id = Number(k.slice(prefix.length));
      if (Number.isInteger(id)) out.push(id);
    }
    return out;
  }
}

export class InMemoryIdentityKeyStore extends IdentityKeyStore {
  private readonly identities: PersistedBytesMap;

  constructor(
    private readonly identityKeyPrivate: PrivateKey,
    private readonly registrationId: number,
    key: Uint8Array,
    path?: string,
  ) {
    super();
    this.identities = new PersistedBytesMap(key, path);
  }

  async getIdentityKey() {
    return this.identityKeyPrivate;
  }

  async getLocalRegistrationId() {
    return this.registrationId;
  }

  async saveIdentity(name: ProtocolAddress, keyPub: PublicKey) {
    const k = key(name);
    const existing = this.identities.get(k);
    const serialized = keyPub.serialize();
    this.identities.set(k, serialized);
    if (
      existing &&
      Buffer.compare(Buffer.from(existing), Buffer.from(serialized)) !== 0
    ) {
      return IdentityChange.ReplacedExisting;
    }
    return IdentityChange.NewOrUnchanged;
  }

  async isTrustedIdentity(
    _name: ProtocolAddress,
    _keyPub: PublicKey,
    _direction: Direction,
  ) {
    // Trust on first use. A real client should prompt the user on changes.
    return true;
  }

  async getIdentity(name: ProtocolAddress): Promise<PublicKey | null> {
    const raw = this.identities.get(key(name));
    return raw ? PublicKey.deserialize(Buffer.from(raw)) : null;
  }
}

export class InMemoryPreKeyStore extends PreKeyStore {
  private readonly keys: PersistedBytesMap;

  constructor(key: Uint8Array, path?: string) {
    super();
    this.keys = new PersistedBytesMap(key, path);
  }

  async savePreKey(id: number, record: PreKeyRecord) {
    this.keys.set(String(id), record.serialize());
  }

  async getPreKey(id: number) {
    const raw = this.keys.get(String(id));

    if (!raw) throw new Error(`No prekey ${id}`);

    return PreKeyRecord.deserialize(Buffer.from(raw));
  }

  async removePreKey(id: number) {
    this.keys.delete(String(id));
  }

  add(id: number, priv: PrivateKey) {
    const record = PreKeyRecord.new(id, priv.getPublicKey(), priv);
    this.keys.set(String(id), record.serialize());
  }

  maxKeyId() {
    return this.keys.maxNumericKey();
  }
}

export class InMemorySignedPreKeyStore extends SignedPreKeyStore {
  private readonly keys: PersistedBytesMap;

  constructor(key: Uint8Array, path?: string) {
    super();
    this.keys = new PersistedBytesMap(key, path);
  }

  async saveSignedPreKey(id: number, record: SignedPreKeyRecord) {
    this.keys.set(String(id), record.serialize());
  }

  async getSignedPreKey(id: number) {
    const raw = this.keys.get(String(id));
    if (!raw) throw new Error(`No signed prekey ${id}`);
    return SignedPreKeyRecord.deserialize(Buffer.from(raw));
  }

  add(id: number, timestamp: number, priv: PrivateKey, signature: Uint8Array) {
    const record = SignedPreKeyRecord.new(
      id,
      timestamp,
      priv.getPublicKey(),
      priv,
      new Uint8Array(signature),
    );
    this.keys.set(String(id), record.serialize());
  }

  maxKeyId() {
    return this.keys.maxNumericKey();
  }
}

export class InMemoryKyberPreKeyStore extends KyberPreKeyStore {
  private readonly keys: PersistedBytesMap;
  // "Used" state is in-memory only; libsignal never queries it back.
  private readonly used = new Set<number>();

  constructor(key: Uint8Array, path?: string) {
    super();
    this.keys = new PersistedBytesMap(key, path);
  }

  async saveKyberPreKey(id: number, record: KyberPreKeyRecord) {
    this.keys.set(String(id), record.serialize());
  }

  async getKyberPreKey(id: number) {
    const raw = this.keys.get(String(id));
    if (!raw) throw new Error(`No kyber prekey ${id}`);
    return KyberPreKeyRecord.deserialize(Buffer.from(raw));
  }

  async markKyberPreKeyUsed(
    id: number,
    _signedPreKeyId: number,
    _baseKey: PublicKey,
  ) {
    this.used.add(id);
  }

  add(
    id: number,
    timestamp: number,
    keyPair: KEMKeyPair,
    signature: Uint8Array,
  ) {
    const record = KyberPreKeyRecord.new(
      id,
      timestamp,
      keyPair,
      new Uint8Array(signature),
    );
    this.keys.set(String(id), record.serialize());
  }

  maxKeyId() {
    return this.keys.maxNumericKey();
  }
}

export class InMemorySenderKeyStore extends SenderKeyStore {
  private readonly keys: PersistedBytesMap;

  constructor(key: Uint8Array, path?: string) {
    super();
    this.keys = new PersistedBytesMap(key, path);
  }

  // Key format: `${sender.name()}.${sender.deviceId()}|${distributionId}`
  // distributionId is already a UUID string from libsignal.
  private k(sender: ProtocolAddress, distributionId: Uuid) {
    return `${key(sender)}|${distributionId}`;
  }

  async saveSenderKey(
    sender: ProtocolAddress,
    distributionId: Uuid,
    record: SenderKeyRecord,
  ) {
    this.keys.set(this.k(sender, distributionId), record.serialize());
  }

  async getSenderKey(sender: ProtocolAddress, distributionId: Uuid) {
    const raw = this.keys.get(this.k(sender, distributionId));
    return raw ? SenderKeyRecord.deserialize(Buffer.from(raw)) : null;
  }
}

export interface ProtocolStores {
  session: InMemorySessionStore;
  identity: InMemoryIdentityKeyStore;
  preKey: InMemoryPreKeyStore;
  signedPreKey: InMemorySignedPreKeyStore;
  kyberPreKey: InMemoryKyberPreKeyStore;
  senderKey: InMemorySenderKeyStore;
}

function storePaths(dir: string) {
  return {
    sessions: join(dir, "sessions.enc"),
    identities: join(dir, "identities.enc"),
    preKeys: join(dir, "preKeys.enc"),
    signedPreKeys: join(dir, "signedPreKeys.enc"),
    kyberPreKeys: join(dir, "kyberPreKeys.enc"),
    senderKeys: join(dir, "senderKeys.enc"),
  };
}

export function createStores(
  identityPrivate: PrivateKey,
  registrationId: number,
  key: Uint8Array,
  persistDir?: string,
): ProtocolStores {
  const p = persistDir ? storePaths(persistDir) : undefined;

  return {
    session: new InMemorySessionStore(key, p?.sessions),
    identity: new InMemoryIdentityKeyStore(
      identityPrivate,
      registrationId,
      key,
      p?.identities,
    ),
    preKey: new InMemoryPreKeyStore(key, p?.preKeys),
    signedPreKey: new InMemorySignedPreKeyStore(key, p?.signedPreKeys),
    kyberPreKey: new InMemoryKyberPreKeyStore(key, p?.kyberPreKeys),
    senderKey: new InMemorySenderKeyStore(key, p?.senderKeys),
  };
}
