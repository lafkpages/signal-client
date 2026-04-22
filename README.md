# @luisafk/signal-client

An unofficial Signal client library built on top of [`@signalapp/libsignal-client`](https://github.com/signalapp/libsignal), using [Bun](https://bun.sh). Links as a secondary device (like Signal Desktop) via QR code provisioning, handles the Signal protocol (key exchange, sealed sender, etc.), and emits decrypted messages as events.

> **Note:** This is an experimental project — not affiliated with or endorsed by Signal.

## Features

- QR-code-based device linking (scan from Signal mobile)
- Signal Protocol encryption/decryption (Double Ratchet, PreKey, Sealed Sender)
- Contact sync via attachment download
- Protobuf-based message parsing (SignalService protos)
- Persistent protocol state (sessions, identity keys, pre-keys) in JSON files

## Setup

You'll need [Bun](https://bun.sh).

```sh
git clone https://github.com/lafkpages/signal-client
cd signal-client
bun install
```

## Usage

```sh
bun run ./src/demo
```

On first run, a QR code is printed to the terminal. Scan it with Signal on your phone to link as a new device. Credentials and protocol state are saved to `state.json` and `store/`, so subsequent runs reconnect automatically.

Incoming messages are decrypted and logged to the console. The library itself exposes a `SignalClient` class that emits `"message"` events — see [src/demo/index.ts](src/demo/index.ts) for an example.

## Storage

**Messages are not stored.** They are decrypted, emitted via the `"message"` event, and discarded. Persisting messages is the caller's responsibility.

What _is_ stored:

- **Account state** (`state.json`) — ACI/PNI identity key pairs, device ID, credentials
- **Protocol stores** (`store/`) — session records, identity keys, pre-keys, signed pre-keys, Kyber pre-keys

All of this is written as **plain unencrypted JSON** by `SignalClient` itself (not just the demo). Files are created with `0o600` permissions (owner read/write only), but the data is not encrypted at rest. Don't run this on a shared machine.
