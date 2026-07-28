# Test data — wire-desktop-forensic

Provenance for every committed test artifact. This repo's fixtures are indexed in
the fleet catalog `ronin-issen/docs/test-data-catalog.md` (cross-reference, not
duplicate).

No purpose-built, publicly downloadable **Wire** IndexedDB forensic sample exists
(confirmed by research — the closest public Electron-messenger LevelDB corpus,
`lxndrblz/forensicsim`, is **Microsoft Teams**, a different Dexie schema). So the
committed fixture is a **real Chromium-authored** IndexedDB store minted on the
host in Wire's documented Dexie schema. See `docs/validation.md` for the honest
tier discussion.

## `wire-indexeddb/http_127.0.0.1_8731.indexeddb.leveldb/`

- **Classification:** `REAL-self` (real Chromium/Blink-authored bytes; scenario
  self-constructed) — tier-2 oracle.
- **Source / authorship:** Minted by driving **Google Chrome** (`--headless=new`)
  against a local page that opens IndexedDB database `wire`, creates the Wire
  Dexie object stores (`conversations`, `events`, `users`, `clients`, `keys`),
  and `put`s one record into each — including a cleartext message
  (`data.content`) and an encrypted message whose `data` is an `ArrayBuffer`
  (opaque Proteus-style body). The bytes (LevelDB key coding, Blink
  `SerializedScriptValue` values) are authored by Chrome, not by us.
- **Wire schema reference:** hunjison, *Forensic Analysis of Wire Messenger in
  Windows OS* — <https://velog.io/@hunjison/Forensic-Analysis-of-Wire-Messenger-in-Windows-OS>
  (the `https_app.wire.com_0.indexeddb.leveldb` store + the `otr_key`).
- **License / redistribution:** self-generated, no third-party rights; CC0-equivalent.
- **Consumed by:** `wire-desktop-core/tests/oracle_minted.rs` (tier-2 oracle) —
  reads the store via `chromium_storage_indexeddb::read_dir`, interprets it, and
  reconciles against the known writes.
- **Ground truth (the known writes):**
  - `conversations/conv-1` → name `Incident Ops`
  - `events/conv-1@ev-1` → cleartext `meet at 9`, from `user-alice`,
    time `2026-01-02T03:04:05.000Z`
  - `events/conv-1@ev-enc` → encrypted (`ArrayBuffer` body), from `user-bob`,
    time `2026-01-02T03:05:00.000Z`
  - `users/user-alice` → name `Alice Example`
  - `clients/client-7f` → model `Wire for macOS`
  - `keys/otr_key` → attachment-key record

### Regenerate the store (mint recipe)

The LevelDB store dir is committed, so no regeneration is normally needed. To
re-mint (verbatim commands):

```bash
MINT=/tmp/wire-mint; rm -rf "$MINT"; mkdir -p "$MINT/www" "$MINT/profile"
# write $MINT/www/index.html — opens IndexedDB "wire", creates the five object
# stores, put()s the six records above (data.content cleartext + an ArrayBuffer
# body), and calls db.close() on tx.oncomplete to flush.
(cd "$MINT/www"; python3 -m http.server 8731 &)
CHROME="/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
"$CHROME" --headless=new --disable-gpu --no-first-run --no-default-browser-check \
  --disable-background-networking --disable-component-update --no-pings \
  --user-data-dir="$MINT/profile" "http://127.0.0.1:8731/index.html" &
CHROME_PID=$!; sleep 8; kill -TERM $CHROME_PID   # clean shutdown flushes leveldb
# fixture = $MINT/profile/Default/IndexedDB/http_127.0.0.1_8731.indexeddb.leveldb
```

The full HTML/JS is in the git history of `docs/validation.md` / the minting
commit. The origin is `http_127.0.0.1_8731` purely because the page was served
from `127.0.0.1:8731`; a real Wire profile's origin is `https_app.wire.com_0` —
the reader is origin-agnostic, so this does not affect interpretation.

### MD5 manifest

`tests/data/` is committed for this small fixture, so hashes live beside the
files here as well:

| file | md5 |
|---|---|
| `…leveldb/000003.log` | `b9f1f4378b5d886d508ab46831b407a8` |
| `…leveldb/CURRENT` | `46295cac801e5d4857d09837238a6394` |
| `…leveldb/LOG` | `968c9d1178aa2ef918414d3b99557dad` |
| `…leveldb/MANIFEST-000001` | `3fd11ff447c1ee23538dc4d9724427a3` |

(The 0-byte `LOCK` file is process state, not data, and is intentionally not
committed.)
