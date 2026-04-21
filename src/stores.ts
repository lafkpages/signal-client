// libsignal-client store implementations with optional file-backed
// persistence. Pass a directory path to `createStores` to enable durability:
// every mutation writes the affected map to its JSON file atomically.
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

function key(addr: ProtocolAddress): string {
  return `${addr.name()}.${addr.deviceId()}`;
}

// ---- Persisted byte-map primitive ------------------------------------------

class PersistedBytesMap {
  private readonly data = new Map<string, Uint8Array>();

  constructor(private readonly path?: string) {
    if (!path || !existsSync(path)) return;
    try {
      const obj = JSON.parse(readFileSync(path, "utf8")) as Record<
        string,
        string
      >;
      for (const [k, v] of Object.entries(obj)) {
        this.data.set(k, Buffer.from(v, "base64"));
      }
    } catch (e) {
      console.warn(`Failed to load ${path}:`, e);
    }
  }

  get(k: string): Uint8Array | undefined {
    return this.data.get(k);
  }

  set(k: string, v: Uint8Array): void {
    this.data.set(k, v);
    this.flush();
  }

  delete(k: string): void {
    this.data.delete(k);
    this.flush();
  }

  /** Returns the largest numeric-looking key, or 0 if none. */
  maxNumericKey(): number {
    let max = 0;
    for (const k of this.data.keys()) {
      const n = Number(k);
      if (Number.isInteger(n) && n > max) max = n;
    }
    return max;
  }

  private flush(): void {
    if (!this.path) return;
    const obj: Record<string, string> = {};
    for (const [k, v] of this.data) {
      obj[k] = Buffer.from(v).toString("base64");
    }
    mkdirSync(dirname(this.path), { recursive: true });
    const tmp = this.path + ".tmp";
    writeFileSync(tmp, JSON.stringify(obj), { mode: 0o600 });
    renameSync(tmp, this.path);
  }
}

// ---- Store implementations -------------------------------------------------

export class InMemorySessionStore extends SessionStore {
  private readonly sessions: PersistedBytesMap;

  constructor(path?: string) {
    super();
    this.sessions = new PersistedBytesMap(path);
  }

  async saveSession(
    name: ProtocolAddress,
    record: SessionRecord,
  ): Promise<void> {
    this.sessions.set(key(name), record.serialize());
  }

  async getSession(name: ProtocolAddress): Promise<SessionRecord | null> {
    const raw = this.sessions.get(key(name));
    return raw ? SessionRecord.deserialize(Buffer.from(raw)) : null;
  }

  async getExistingSessions(
    addresses: ProtocolAddress[],
  ): Promise<SessionRecord[]> {
    const out: SessionRecord[] = [];
    for (const a of addresses) {
      const r = await this.getSession(a);
      if (!r) throw new Error(`No session for ${key(a)}`);
      out.push(r);
    }
    return out;
  }
}

export class InMemoryIdentityKeyStore extends IdentityKeyStore {
  private readonly identities: PersistedBytesMap;

  constructor(
    private readonly identityKeyPrivate: PrivateKey,
    private readonly registrationId: number,
    path?: string,
  ) {
    super();
    this.identities = new PersistedBytesMap(path);
  }

  async getIdentityKey(): Promise<PrivateKey> {
    return this.identityKeyPrivate;
  }

  async getLocalRegistrationId(): Promise<number> {
    return this.registrationId;
  }

  async saveIdentity(
    name: ProtocolAddress,
    keyPub: PublicKey,
  ): Promise<IdentityChange> {
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
  ): Promise<boolean> {
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

  constructor(path?: string) {
    super();
    this.keys = new PersistedBytesMap(path);
  }

  async savePreKey(id: number, record: PreKeyRecord): Promise<void> {
    this.keys.set(String(id), record.serialize());
  }

  async getPreKey(id: number): Promise<PreKeyRecord> {
    const raw = this.keys.get(String(id));
    if (!raw) throw new Error(`No prekey ${id}`);
    return PreKeyRecord.deserialize(Buffer.from(raw));
  }

  async removePreKey(id: number): Promise<void> {
    this.keys.delete(String(id));
  }

  add(id: number, priv: PrivateKey): void {
    const record = PreKeyRecord.new(id, priv.getPublicKey(), priv);
    this.keys.set(String(id), record.serialize());
  }

  maxKeyId(): number {
    return this.keys.maxNumericKey();
  }
}

export class InMemorySignedPreKeyStore extends SignedPreKeyStore {
  private readonly keys: PersistedBytesMap;

  constructor(path?: string) {
    super();
    this.keys = new PersistedBytesMap(path);
  }

  async saveSignedPreKey(
    id: number,
    record: SignedPreKeyRecord,
  ): Promise<void> {
    this.keys.set(String(id), record.serialize());
  }

  async getSignedPreKey(id: number): Promise<SignedPreKeyRecord> {
    const raw = this.keys.get(String(id));
    if (!raw) throw new Error(`No signed prekey ${id}`);
    return SignedPreKeyRecord.deserialize(Buffer.from(raw));
  }

  add(
    id: number,
    timestamp: number,
    priv: PrivateKey,
    signature: Uint8Array,
  ): void {
    const record = SignedPreKeyRecord.new(
      id,
      timestamp,
      priv.getPublicKey(),
      priv,
      new Uint8Array(signature),
    );
    this.keys.set(String(id), record.serialize());
  }

  maxKeyId(): number {
    return this.keys.maxNumericKey();
  }
}

export class InMemoryKyberPreKeyStore extends KyberPreKeyStore {
  private readonly keys: PersistedBytesMap;
  // "Used" state is in-memory only; libsignal never queries it back.
  private readonly used = new Set<number>();

  constructor(path?: string) {
    super();
    this.keys = new PersistedBytesMap(path);
  }

  async saveKyberPreKey(id: number, record: KyberPreKeyRecord): Promise<void> {
    this.keys.set(String(id), record.serialize());
  }

  async getKyberPreKey(id: number): Promise<KyberPreKeyRecord> {
    const raw = this.keys.get(String(id));
    if (!raw) throw new Error(`No kyber prekey ${id}`);
    return KyberPreKeyRecord.deserialize(Buffer.from(raw));
  }

  async markKyberPreKeyUsed(
    id: number,
    _signedPreKeyId: number,
    _baseKey: PublicKey,
  ): Promise<void> {
    this.used.add(id);
  }

  add(
    id: number,
    timestamp: number,
    keyPair: KEMKeyPair,
    signature: Uint8Array,
  ): void {
    const record = KyberPreKeyRecord.new(
      id,
      timestamp,
      keyPair,
      new Uint8Array(signature),
    );
    this.keys.set(String(id), record.serialize());
  }

  maxKeyId(): number {
    return this.keys.maxNumericKey();
  }
}

export class InMemorySenderKeyStore extends SenderKeyStore {
  private readonly keys: PersistedBytesMap;

  constructor(path?: string) {
    super();
    this.keys = new PersistedBytesMap(path);
  }

  // Key format: `${sender.name()}.${sender.deviceId()}|${distributionId}`
  // distributionId is already a UUID string from libsignal.
  private k(sender: ProtocolAddress, distributionId: Uuid): string {
    return `${key(sender)}|${distributionId}`;
  }

  async saveSenderKey(
    sender: ProtocolAddress,
    distributionId: Uuid,
    record: SenderKeyRecord,
  ): Promise<void> {
    this.keys.set(this.k(sender, distributionId), record.serialize());
  }

  async getSenderKey(
    sender: ProtocolAddress,
    distributionId: Uuid,
  ): Promise<SenderKeyRecord | null> {
    const raw = this.keys.get(this.k(sender, distributionId));
    return raw ? SenderKeyRecord.deserialize(Buffer.from(raw)) : null;
  }
}

export type ProtocolStores = {
  session: InMemorySessionStore;
  identity: InMemoryIdentityKeyStore;
  preKey: InMemoryPreKeyStore;
  signedPreKey: InMemorySignedPreKeyStore;
  kyberPreKey: InMemoryKyberPreKeyStore;
  senderKey: InMemorySenderKeyStore;
};

function storePaths(dir: string): {
  sessions: string;
  identities: string;
  preKeys: string;
  signedPreKeys: string;
  kyberPreKeys: string;
  senderKeys: string;
} {
  return {
    sessions: join(dir, "sessions.json"),
    identities: join(dir, "identities.json"),
    preKeys: join(dir, "preKeys.json"),
    signedPreKeys: join(dir, "signedPreKeys.json"),
    kyberPreKeys: join(dir, "kyberPreKeys.json"),
    senderKeys: join(dir, "senderKeys.json"),
  };
}

export function createStores(
  identityPrivate: PrivateKey,
  registrationId: number,
  persistDir?: string,
): ProtocolStores {
  const p = persistDir ? storePaths(persistDir) : undefined;
  return {
    session: new InMemorySessionStore(p?.sessions),
    identity: new InMemoryIdentityKeyStore(
      identityPrivate,
      registrationId,
      p?.identities,
    ),
    preKey: new InMemoryPreKeyStore(p?.preKeys),
    signedPreKey: new InMemorySignedPreKeyStore(p?.signedPreKeys),
    kyberPreKey: new InMemoryKyberPreKeyStore(p?.kyberPreKeys),
    senderKey: new InMemorySenderKeyStore(p?.senderKeys),
  };
}
