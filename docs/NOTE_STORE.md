# NOTE_STORE.md — on-card byte custody

**Status:** design, 2026-10-21. Nothing here is built yet. Decided: D1 (separate package) and the
duress PIN wipes the notes (D5). Still open (§9): the metadata size, the entry count and the tag,
which wait on measurements.
**Scope:** a store for opaque, signed bearer records ("notes") of roughly 1–8 KB each, kept on the
card next to the keys that own them, so the card alone is the complete wallet.

---

## 1. What the store is, and is not

**It is byte custody.** The card keeps the bytes and returns them unchanged. A note is already
signed by whoever issued it, and its owner key is derived from the seed. The card never parses a
note, never checks its signatures and never assembles one. The host verifies a note before writing
it and after reading it.

**It is not secret storage.** A note without its owner key cannot be spent. All the same, the store
is PIN-gated end to end, because the list of notes reveals what the holder owns.

**Non-goals:** parsing note formats, enforcing spend rules, and synchronising with other devices.
Spend authorizations are signed by the existing SIGN command, which this design leaves unchanged.

## 2. Constraints, measured on a J3R200 (`ONMETAL_REPORT.md`)

| Constraint | Value | Consequence |
|---|---|---|
| Free NVM after the fork | 84,868 B (probe still installed) | The pool is about 64 KB, which leaves room for code growth |
| Free CLEAR_ON_RESET RAM | **94 B** | **No new transient buffers.** I/O goes through the APDU buffer (a global array) |
| Command payload in SC V2 | 255 − 5 (inner header) − 8 (CCM tag) = **242 B** | Write chunks carry ≤ 240 B of data |
| Response payload in SC V2 | 247 − 2 (inner SW) = **245 B** | Read chunks return ≤ 240 B |
| Short APDUs only | 255-byte class (applet and Shell firmware) | A 1.5 KB note takes about 7 commands each way |
| No garbage collection | — | The whole pool is allocated once, at install |
| NFC tearing | The card browns out off the sweet spot | Every multi-APDU operation must survive a tear at any point |

## 3. Decisions

### D1. The store lives in its own package, not in the Keycard applet *(decided)*

Java Card 3.0.5 has no in-place applet upgrade. GlobalPlatform Amendment H (ELF upgrade, which
preserves data) exists on some JCOP versions but is unverified on this card and is not relied on
here. So every fix to the Keycard applet is a GP delete plus a reinstall, and that destroys all of
the applet's persistent data. For the seed that is acceptable,
because it comes back from the recovery phrase. Notes come back only from the wallet's encrypted
backup on the desktop, and **any note received since the last backup exists only on the card.** So the store is a separate package with a frozen, minimal interface. The Keycard package
depends on it; it depends on nothing. The Keycard applet can then be replaced as often as needed
while the notes stay put.

- **How it is reached.** The host talks only to the Keycard applet, which already owns the secure
  channel and the PIN. The Keycard applet checks its own state and calls the store through a
  `Shareable` interface. The store hands that interface only to the Keycard applet's AID, checked
  with the client AID in `getShareableInterfaceObject`. Data crosses the firewall in the APDU
  buffer, which is a global array.
- **Crypto stays in the Keycard applet.** The SHA-256 at commit (D3) is computed by the Keycard
  applet with its existing `MessageDigest`, reading blocks through the interface. The store has no
  crypto objects, so it needs no RAM for crypto state. That matters with 94 B left.
- **The cost:** one more package and applet instance, a few KB of NVM, and an interface we commit
  to never changing. If the store's own format has to change, the notes are lost. That is why it
  stays deliberately minimal.

The alternative is to put the store inside the Keycard applet. That is simpler, and it saves a few
KB and the firewall plumbing. But every applet update then wipes every note, unless the notes are
first moved off the card and back. That is acceptable for a development build. It is not
acceptable for a card that is a wallet.

### D2. Fixed 256-byte blocks with a chain table

The pool is `B` blocks of 256 bytes, plus a `next[B]` table of shorts (`0x7FFF` marks the end of a
chain). A note of `len` bytes uses `ceil(len / 256)` blocks chained from its directory entry.

**There is no free list.** A block is free exactly when no live entry's chain reaches it. BEGIN and
STATUS compute that by walking the live chains, at most `B` steps, and mark a bitmap in the APDU
buffer, past the command data (`B/8` bytes: 31 B for 248 blocks). So delete and wipe never touch the
chain table, and nothing has to be kept consistent across a tear. Because all blocks are the same size, the pool never fragments; the waste
averages 128 B per note. Variable size is required. Measured container sizes are about
692 B + 290 B per pair (2 pairs 1,272 B; 3 pairs 1,562 B; 5 pairs 2,142 B; 8 pairs 3,012 B), up to
about 7.6 KB at 24 pairs. Fixed-size slots would either refuse large notes or waste most of their
space on small ones.

Block storage is a small number of `byte[8192]` arrays, each holding 32 blocks. That keeps every
array under JavaCard's 32,767-byte array limit and avoids per-object overhead for each block.

### D3. Two-phase, resumable, tear-safe writes

1. **BEGIN** `(tag, meta, len, sha256)`: picks free blocks and writes their chain cells
   non-atomically. A tear here leaves those cells unreachable, so they stay free. It then writes the
   entry as `WRITING` in one atomic step. It is refused if the tag is already present.
2. **WRITE** `(entry, offset, ≤240 B)`: non-atomic copies into the blocks. The writes are
   **addressed by offset**, so they can be sent in any order and repeated. After a tear the host
   lists the store, finds the `WRITING` entry and resends the missing chunks. On a fussy NFC link,
   that resumability is the difference between "tap again" and "start over".
3. **COMMIT** `(entry)`: the Keycard applet hashes the `len` bytes and compares the result with the
   BEGIN hash. If they match, it flips the entry to `HELD` in one atomic write. A mismatch returns
   `6A80` and the entry stays `WRITING`.

A note becomes visible as `HELD` only through that single atomic flip, so a tear can never leave a
half-written note that looks valid. Each tear point:

| Torn during | State afterwards | Recovery |
|---|---|---|
| BEGIN | The entry was not written, so the chain cells are unreachable and still free | Repeat BEGIN |
| WRITE | Entry `WRITING`, some blocks partly written | Resend chunks (the hash check catches any gaps) |
| COMMIT | The flip is atomic: either `WRITING` or `HELD` | LIST shows which |
| DELETE | One status byte, atomic: either intact or gone | LIST shows which |
| Duress wipe | The epoch, atomic | Nothing to recover |

`ABORT (entry)` frees a `WRITING` entry. A new BEGIN does **not** reclaim stale `WRITING` entries
on its own, because they may be a resumable upload. The host decides when to abort them.

### D4. Directory entry, 39 + `M` bytes (`M` = meta length, an install parameter)

| Field | Size | Meaning |
|---|---|---|
| status | 1 | `FREE` / `WRITING` / `HELD` |
| epoch | 2 | Store epoch at write. An entry whose epoch is not the current one is dead (D5). On the 65,536th wipe the epoch would wrap, and old entries could match it again; that one wipe also sets every entry's status to FREE (slow, once) |
| len | 2 | Note length in bytes |
| first | 2 | First block of the chain |
| tag | 32 | Unique key chosen by the host, e.g. the note's event id. Used to prevent duplicates |
| meta | `M` (16 assumed) | Opaque to the card, chosen by the host, e.g. owner-key index (4), amount (8), flags (1). Rewritable with SET META |

`meta` is what lets a terminal show a balance or find the note for a given owner index **without
reading every note**. It is the only field the host may change after commit, and the change is
atomic.

### D5. Access control

- **Every** command requires an open secure channel and a verified PIN, including LIST and STATUS.
  This is the existing gate used by SIGN and EXPORT KEY.
- **The duress PIN wipes the notes** *(decided)*. Verifying the alternate PIN increments the store
  epoch. That is one atomic 2-byte write, so every existing entry is dead at once and the response
  takes no longer than an ordinary VERIFY PIN. A slow wipe would tell the person applying pressure
  what had happened.
  - **What the duress session sees:** after the wipe, an empty store with full free capacity, so
    nothing is left over to explain.
  - **Physical overwrite:** the wipe is logical. Dead blocks keep their bytes until a later BEGIN
    reuses and overwrites them, and dead entries keep their tag and meta until reused. That data
    stays inside the secure element and no command can reach it. Overwriting all 63 KB at wipe time
    would take seconds and give the wipe away.
  - **The cost:** a duress wipe is unrecoverable on the card. The notes come back from the
    desktop's encrypted backup, which covers everything except notes received since the last
    backup. The wallet should back up after every receipt anyway (`backup.rs`: "the blobs on every
    single receipt").
- **FACTORY RESET wipes the store** with the same epoch bump, and it inherits our PIN gate on wipe.

### D6. Allocation and sizing

The pool is allocated in the store applet's install, sized by install parameters
`[blocks:2][entries:1][metaLen:1]`, with defaults for the J3R200. The metadata length and the entry
count are deliberately install-time values (§9). The wire format carries `metaLen` (STATUS reports
it, and LIST and SET META use it), so tuning them later is a reinstall, not an interface change. If allocation fails, the install fails with a
readable error rather than leaving the card half-provisioned. Install the store **before** the
Keycard package, because the Keycard package depends on it.

| J3R200 default | |
|---|---|
| Blocks | 248 × 256 B = 63,488 B |
| Chain table | 496 B |
| Directory | 64 × 55 B = 3,520 B (with M = 16) |
| **Store total** | **≈ 67.5 KB** of the 84.9 KB measured. About 17 KB stays free for code growth (for example verify-after-sign) |
| Capacity | 49 two-pair notes (1,272 B, 5 blocks); 35 three-pair (7 blocks); 27 five-pair (9 blocks); 8 at 24 pairs (30 blocks) |

On a J3R452 the same CAP takes larger install parameters. Nothing else changes.

## 4. Commands (CLA `0x80`, all inside SC V2)

| INS | Name | P1 | P2 | Data in | Data out |
|---|---|---|---|---|---|
| `B0` | STATUS | — | — | — | `version:1 blocksTotal:2 blocksFree:2 entriesTotal:1 entriesFree:1 metaLen:1` |
| `B1` | LIST | first entry | — | — | as many `[entry:1 status:1 len:2 tag:32 meta:M]` as fit in 240 B (4 with M = 16); the last byte is the next entry index, or `FF` |
| `B2` | BEGIN | — | — | `len:2 sha256:32 tag:32 meta:M` | `entry:1` |
| `B3` | WRITE | entry | — | `offset:2 data:≤240` | — |
| `B4` | COMMIT | entry | — | — | — |
| `B5` | READ | entry | — | `offset:2 length:1` (≤240) | data |
| `B6` | DELETE | entry | `00` = HELD, `01` = abort WRITING | `tag:32` (must match: guards against deleting the wrong entry) | — |
| `B7` | SET META | entry | — | `tag:32 meta:M` | — |

Status words:

| SW | Meaning |
|---|---|
| `6A84` | No free blocks or entries |
| `6A89` | Tag already present |
| `6A88` | Entry not found, or dead (wiped epoch) |
| `6A80` | Hash mismatch at commit, or bad offset or length |
| `6985` | Wrong entry state, or tag mismatch |
| `6982` | No PIN or no secure channel |

Entry indices are not stable across a delete and re-add, so the tag is the identity of a note. The
`tag` check on DELETE and SET META makes a stale index fail safely instead of acting on another
note.

## 5. RAM budget, per command

None of the commands allocates anything. Data moves APDU buffer ↔ blocks with `arrayCopyNonAtomic`.
The open-write state lives in the persistent directory entry, not in RAM. COMMIT's hash uses the
Keycard applet's existing `MessageDigest` and reads block-sized pieces through the APDU buffer.
**The store adds 0 B of transient memory.**

Atomicity needs only single-entry writes: one entry at BEGIN, one status byte at COMMIT or DELETE,
the 2-byte epoch at a wipe. The largest is one entry (39 + M bytes) through the commit buffer, so
commit capacity is not a concern. BEGIN's free-block bitmap uses scratch space in the APDU buffer
past the command data.

## 6. A receive and a spend, end to end

```
RECEIVE  verify the note on the host → BEGIN(len, sha256, tag=event_id, meta=owner index…)
         → WRITE × ceil(len/240) → COMMIT
         (a tear at any point → LIST → resend the missing chunks → COMMIT)

SPEND    LIST / read meta → READ × n → verify on the host → SIGN the spend authorization (existing)
         → broadcast → on confirmation: DELETE(entry, tag)
         (never delete before confirmation: until then the card may hold the only copy)
```

Marking a note "pending" while its spend is in flight is the host's business, through SET META.
The card does not link SIGN to a note.

## 7. Wear

A receive writes about `len` bytes plus one entry and the chain-table cells. A delete rewrites one
entry and the chain-table cells. JCOP NVM endurance is in the hundreds of thousands of cycles, so at
note rates wear is not an issue. The directory and chain table are the most-written cells; if a
fuzz test shows a hot spot, rotate the entry allocation.

## 8. Tests

- **Simulator:**
  - Every command and every status word.
  - Tear injection at each step (fail the APDU mid-WRITE, then resume).
  - Duress wipe: the epoch bump, an empty store afterwards, and response time unchanged.
  - Fill to capacity.
  - Hash mismatch.
  - Stale-index DELETE.
  - FACTORY RESET wipe.
  - A Keycard applet reinstall that leaves notes intact. This is D1's whole point, so it gets its own
    test.
- **On the card:**
  - Fill the pool and read everything back.
  - Measure free NVM before and after the store install.
  - Time VERIFY PIN with the main PIN and with the duress PIN, with the store full: they must be
    indistinguishable.
  - Lift the card mid-WRITE on purpose over NFC, then resume.
  - Time a 1.5 KB receive and spend.

## 9. Open decisions

Decided 2026-10-21: separate package (D1); the duress PIN wipes the notes (D5); the desktop's
encrypted backup is the recovery path for note bytes; an 8 KB maximum note size (24 pairs is about
7.6 KB).

Still open. These need data first, so the build makes them install parameters:

1. **`meta` contents and size.** The candidate is owner index (4) + amount (8) + flags (1), which
   comes to 16 B with room to spare. Confirm against what the wallet needs to show a balance and
   pick a note without reading every note.
2. **The tag.** It must be unique per note. Is it the event id, or the ephemeral public key (the
   ledger key)? If several notes can come from one print event, the event id is not unique.
3. **Entries vs blocks.** This depends on the real mix of pairs per note. 64 entries cover the
   worst case (all 2-pair notes: 49) with margin. Settle it with the on-card fill test (§8) against
   a realistic mix.
