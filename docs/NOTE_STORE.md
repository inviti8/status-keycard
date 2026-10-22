# NOTE_STORE.md — on-card byte custody

**Status:** built, 2026-10-22: `notes/src` and `NoteStoreTest`.
- **First version verified on a J3R200:** 11/11 on the card. Capacity matched, the store took
  71.3 KB at the default sizes, and a typical receive took about 4 s over NFC (`ONMETAL_REPORT.md`).
- **Duress change verified on the J3R200:** the duress PIN now hides the notes behind a fixed share
  instead of wiping them (D5). 12/12 on the card and 18/18 in the simulator. On-card capacity matches
  the simulator.

Decided: D1 (separate package), duress = hide with a fixed share (D5), the tag is the ephemeral key,
and the meta layout (§9).
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

1. **BEGIN** `(len, tag, meta)`: picks free blocks and writes their chain cells
   non-atomically. A tear here leaves those cells unreachable, so they stay free. It then writes the
   entry as `WRITING` in one atomic step. It is refused if the tag is already present.
2. **WRITE** `(entry, offset, ≤240 B)`: non-atomic copies into the blocks. The writes are
   **addressed by offset**, so they can be sent in any order and repeated. After a tear the host
   lists the store, finds the `WRITING` entry and resends the missing chunks. On a fussy NFC link,
   that resumability is the difference between "tap again" and "start over".
3. **COMMIT** `(entry, sha256)`: the Keycard applet hashes the `len` bytes and compares the result
   with the hash sent. The hash travels with COMMIT, not BEGIN: the host has the note in hand, and
   storing a hash per entry would cost 32 B × 64. If they match, it flips the entry to `HELD` in one atomic write. A mismatch returns
   `6A80` and the entry stays `WRITING`.

A note becomes visible as `HELD` only through that single atomic flip, so a tear can never leave a
half-written note that looks valid. Each tear point:

| Torn during | State afterwards | Recovery |
|---|---|---|
| BEGIN | The entry was not written, so the chain cells are unreachable and still free | Repeat BEGIN |
| WRITE | Entry `WRITING`, some blocks partly written | Resend chunks (the hash check catches any gaps) |
| COMMIT | The flip is atomic: either `WRITING` or `HELD` | LIST shows which |
| DELETE | One status byte, atomic: either intact or gone | LIST shows which |
| Wipe (FACTORY RESET) | The epoch, atomic | Nothing to recover |

`ABORT (entry)` frees a `WRITING` entry. A new BEGIN does **not** reclaim stale `WRITING` entries
on its own, because they may be a resumable upload. The host decides when to abort them.

### D4. Directory entry, 39 + `M` bytes (`M` = meta length, an install parameter)

| Field | Size | Meaning |
|---|---|---|
| status | 1 | `FREE` / `WRITING` / `HELD` in the low bits. The top bit is the owning tree: 0 = main PIN, 1 = duress PIN (D5) |
| epoch | 2 | Store epoch at write. An entry whose epoch is not the current one is dead (D5). On the 65,536th wipe the epoch would wrap, and old entries could match it again; that one wipe also sets every entry's status to FREE (slow, once) |
| len | 2 | Note length in bytes |
| first | 2 | First block of the chain |
| tag | 32 | Unique key chosen by the host. For Kenter it is the note's **ephemeral public key**, the mint's on-chain primary key (`DataKey::Token`), so a LIST row maps straight to a ledger lookup. Not the event id, which is caller-supplied and not unique |
| meta | `M` (16 by default) | Opaque to the card, rewritable with SET META. Kenter's layout is in §9 |

`meta` is what lets a terminal show a balance or find the note for a given owner index **without
reading every note**. It is the only field the host may change after commit, and the change is
atomic.

### D5. Access control

- **Every** command requires an open secure channel and a verified PIN, including LIST and STATUS.
  This is the existing gate used by SIGN and EXPORT KEY.
- **The duress PIN hides the notes; it does not wipe them** *(decided)*. This matches standard
  Keycard, where the duress PIN opens a decoy wallet and destroys nothing. Every note records the
  tree that wrote it, main PIN or duress PIN, in its status byte. Each tree:
  - lists, reads, counts and deletes only its own notes;
  - gets `6A88` (not found) for the other tree's entry indexes;
  - compares tags only against its own notes. Refusing a duplicate the other tree holds would
    reveal that note exists.

  The next main-PIN unlock shows everything as before. The duress PIN also derives decoy Ed25519
  keys (`KeycardApplet.ed25519ChainCode`), so the authority to spend stays hidden along with the
  bytes.
- **The duress tree has a fixed share, so its view gives nothing away.** It owns 1/8 of the blocks
  and entries (31 and 8 at the default sizes); the main tree owns the rest. Each tree's STATUS is
  computed from its own share and its own notes only. Whatever the main tree holds, the duress PIN
  always sees the same store: empty, with full free space, about 4 decoy notes' worth. Without the
  share, the totals would come out as capacity minus the hidden notes, and anyone who knows the
  default sizes could do the arithmetic. The cost is about 12% of the main tree's capacity (§9).
  - **Residual:** BEGIN still walks every chain to find free blocks, so its time varies slightly
    with what the card holds. The difference is far below NFC framing noise, but it is not exactly
    zero.
- **Limits inherent to a duress PIN.** Someone holding the duress PIN can deny the holder access
  but cannot reach the real wallet:
  - **Lock-out:** wrong guesses after a duress unlock block the main PIN, and the duress PIN no
    longer resets its counter (upstream #129). A PUK changed from a duress session can only ever
    unblock the duress PIN. Notes and keys then come back from the desktop backup and the phrase.
  - **Wipe:** FACTORY RESET is allowed under the duress PIN, like the main PIN, so the two stay
    indistinguishable. It wipes both trees.
- **FACTORY RESET wipes the store** (both trees) with one epoch increment, and it inherits our PIN gate
  on wipe.

### D7. Owner-index counter *(decided 2026-10-22; verified on the J3R200)*

Kenter never reuses an owner index (`OWNER_KEYS.md` §4): reuse points two payers at one
commitment and links their payments. A terminal with no state of its own, the Shell, cannot pick
the next index from the notes on the card. "1 + the highest owner index held" hands out a used
index again as soon as the highest-index note is reclaimed, or after a receive that was shown but
never stored. So the store keeps the counter:

- **NEXT INDEX** returns the next index and advances the counter. The advance is persisted, with
  one atomic write, **before** the response, so a response lost to a tear only skips an index;
  one is never handed out twice. Gaps cost nothing; duplicates cost privacy.
- **ADVANCE INDEX** raises the counter to at least a value and never lowers it. A desktop that
  issued indexes itself (`next_owner_index` in its state) syncs the card with it. A value of 0 just
  reads the counter.
- **One counter per tree,** so the duress PIN's indexes say nothing about the main tree.
- **It starts at 1** (0 is Kenter's reusable receive tag) and stops after `0x7FFFFFFF`, the largest
  index a hardened path component carries (`6A84` after that).
- **It is never reset:** not by FACTORY RESET, and not by the duress PIN. A card restored from the
  same phrase would otherwise restart at 1 and reuse old indexes. Only reinstalling the store
  package resets it, the same event that loses the notes, so after one the host must ADVANCE it
  past every index it knows.

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
| Main tree | 217 blocks / 56 entries: 43 two-pair notes, 31 three-pair, 27 four-pair, 14 at 10 pairs, 7 at 24 pairs |
| Duress tree | 31 blocks / 8 entries (the fixed 1/8 share): about 4 three-pair decoy notes |

On a J3R452 the same CAP takes larger install parameters. Nothing else changes.

## 4. Commands (CLA `0x80`, all inside SC V2)

| INS | Name | P1 | P2 | Data in | Data out |
|---|---|---|---|---|---|
| `B0` | STATUS | — | — | — | `version:1 blocksTotal:2 blocksFree:2 entriesTotal:1 entriesFree:1 metaLen:1` |
| `B1` | LIST | first entry | — | — | as many `[entry:1 status:1 len:2 tag:32 meta:M]` as fit in 240 B (4 with M = 16); the last byte is the next entry index, or `FF` |
| `B2` | BEGIN | — | — | `len:2 tag:32 meta:M` | `entry:1` |
| `B3` | WRITE | entry | — | `offset:2 data:≤240` | — |
| `B4` | COMMIT | entry | — | `sha256:32` | — |
| `B5` | READ | entry | — | `offset:2 length:1` (≤240) | data |
| `B6` | DELETE | entry | `00` = HELD, `01` = abort WRITING | `tag:32` (must match: guards against deleting the wrong entry) | — |
| `B7` | SET META | entry | — | `tag:32 meta:M` | — |
| `B8` | NEXT INDEX | — | — | — | `index:4`: the owner index handed out (D7) |
| `B9` | ADVANCE INDEX | — | — | `value:4` (≤ `0x80000000`) | `next:4`: the counter after raising it to at least `value`; `0` reads it |

Status words:

| SW | Meaning |
|---|---|
| `6A84` | No free blocks or entries |
| `6A89` | Tag already present |
| `6A88` | Entry not found: dead (wiped epoch), or owned by the other PIN's tree |
| `6A80` | Hash mismatch at commit, or bad offset or length |
| `6985` | Wrong entry state, tag mismatch, or PIN not verified (the Keycard applet's convention) |
| `6A82` | Store package not installed |

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
RECEIVE  verify the note on the host → BEGIN(len, tag = ephemeral key, meta) → WRITE × ceil(len/240)
         → COMMIT(sha256) → back up on the desktop → SET META (backed_up)
         (a tear at any point → LIST → resend the missing chunks → COMMIT)

SPEND    LIST / meta → READ × n → verify on the host → deliver the bytes to the payee
         → SIGN the spend authorization (existing) → spend() on-chain → SET META (spent_away)
```

The card does not link SIGN to a note and never deletes anything on its own. Three host-side rules
follow, from the Kenter wallet:

- **Bytes reach the payee before the owner pointer moves.** Once `spend()` lands, this holder's key
  no longer matches the live commitment. A payee who does not have the file by then has nothing to
  redeem with, and the note is stranded (`kenter-ui` `pay.rs`).
- **A spent note is marked, not deleted.** The record carries the export history, and the wallet
  keeps it (`spent_away`). DELETE is a **separate reclaim the holder chooses** to free a slot. It is
  not the last step of a spend.
- **Bearer handovers are invisible.** A handover is a file and nothing else, with no transaction to
  wait for, so a bearer note on the card is never auto-deleted.

## 7. Wear

A receive writes about `len` bytes plus one entry and the chain-table cells. A delete rewrites one
entry and the chain-table cells. JCOP NVM endurance is in the hundreds of thousands of cycles, so at
note rates wear is not an issue. The directory and chain table are the most-written cells; if a
fuzz test shows a hot spot, rotate the entry allocation.

## 8. Tests

- **Simulator:**
  - Every command and every status word.
  - Tear injection at each step (fail the APDU mid-WRITE, then resume).
  - Duress hiding: each PIN sees only its own notes, the duress view is fixed whatever the main tree holds, and the duress share fills on its own.
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

## 9. Decisions

Decided 2026-10-21/22:

- **Package:** separate (D1).
- **Duress PIN:** hides the notes behind a fixed 1/8 share, and derives decoy Ed25519 keys (D5).
  This replaces "wipes the notes" (2026-10-21), which differed from how the standard duress PIN
  works and could be detected by someone who knew what the card held.
- **Recovery:** the desktop's encrypted backup is the recovery path for note bytes.
- **Tag:** the ephemeral public key.
- **Maximum note size: 8 KB.** That is 24 pairs at about 7.6 KB, which is also the mainnet cap
  that `REDEEM.md` §5 recommends on instruction-budget grounds. The two limits arrive at the same
  number from different directions. The hard ceiling is 33 pairs, beyond which Path B redemption no
  longer fits Soroban's budget.

**Kenter's meta layout (16 B, the default)**, taken from what the billfold renders per note
(`NoteCard`):

| Field | Bytes | Note |
|---|---|---|
| amount | 8 | u64 |
| owner_index | 4 | u32, spend mode. Not `owner_commitment`: that is re-derivable on the card from the index |
| pairs | 1 | Needed for `redeems_for` = face − `node_fee` × 2 × pairs. Store the count, not the result, because `node_fee` is mint config |
| exposure | 1 | Parties that may hold a redeemable copy (saturating) |
| flags | 1 | spend_mode, spent_away, marked_spent, **backed_up** |
| spare | 1 | — |

`backed_up` is how the wallet can tell the holder that a note exists only on the card: a lost or
broken card, or a forced wipe, loses every note not yet backed up. If 24 B is
affordable, the next field is `imported_at` (u32 seconds) for ordering; `label` belongs in the
desktop backup.

**Capacity.** The main tree at the J3R200 default (248 blocks / 64 entries, less the duress
share: 217 blocks / 56 entries), measured in the simulator by filling the store:

| Pairs | Note size | Main-tree notes | Without the duress share |
|---|---|---|---|
| 2 | 1,272 B | 43 | 49 |
| 3 | 1,562 B | 31 | 35 |
| 4 | 1,852 B | 27 | 31 |
| 10 | 3,592 B | 14 | 16 |
| 24 | 7,652 B | 7 | 8 |

Both columns were measured on the card, and both matched the simulator exactly. The realistic
mix is 3–4 pairs: the UI default is 3, a node network uses nodes + 2, and the deployed testnet
maximum is 10. That means roughly **27–31 notes per J3R200**. Entries run out only for notes under
about 1 KB, so the entry count is not the constraint.
