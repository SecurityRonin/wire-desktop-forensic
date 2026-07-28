# wire-desktop-core

Reader for **Wire desktop** (Electron) messenger artifacts. Interprets the
Chromium IndexedDB-over-LevelDB Dexie object stores
(`https_app.wire.com_0.indexeddb.leveldb`) into typed Wire records
(conversations, events, users, clients) and a chronological timeline.

Client-side-encrypted (Proteus) message bodies are surfaced as unrecoverable —
Wire's message key is not in the Chromium OS Safe Storage — rather than
fabricating plaintext.

See the [repository README](https://github.com/SecurityRonin/wire-desktop-forensic).
