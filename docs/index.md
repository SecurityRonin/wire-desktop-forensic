# wire-desktop-forensic

A two-crate suite for **Wire desktop** (Electron) messenger artifacts:

- **`wire-desktop-core`** — reads the Chromium IndexedDB Dexie object stores
  (`https_app.wire.com_0.indexeddb.leveldb`) and interprets them into typed Wire
  records (conversations, events, users, clients) and a chronological timeline.
- **`wire-desktop-forensic`** — audits an interpreted store into canonical
  `forensicnomicon::report::Finding`s.

It layers on the Wave-2 [`chromium-storage-indexeddb`](https://github.com/SecurityRonin/chromium-storage-forensic)
reader and reuses the Wire artifact spec from
[`forensicnomicon`](https://github.com/SecurityRonin/forensicnomicon).

## What it does and does not recover

Wire message content is **client-side (Proteus) encrypted**, and Wire's message
key is **not** held in the Chromium OS Safe Storage — so it is not recoverable
from this artifact. The reader recovers everything that is in cleartext
(conversation/user/client metadata, event timestamps, senders, message *type*,
and any cleartext message bodies) and marks encrypted bodies as unrecoverable
rather than fabricating plaintext. See [Purpose & Scope](PRD.md) and
[Validation](validation.md).

## Quick links

- [Purpose & Scope](PRD.md)
- [Validation](validation.md)
- [Decision records](decisions/0001-reader-analyzer-split.md)
