# On-metal report — Core C on a J3R200

**Date:** 2026-10-21 · **Branch:** `feat/stellar-ed25519` · **Result:** Core C runs on the chip
after two configuration changes; the full suite passes on the card.

## Card and setup

| | |
|---|---|
| Card | Keycard developer card, NXP J3R200 (JCOP4 P71, CPLC IC type `D321`) |
| GP | 2.3, SCP02 i=55, one key set (KVN `01`), the Keycard development key (`c212e073…`, as in the SDK) |
| As delivered | Keycard applet pre-installed, uninitialized (deleted for this run) |
| `JCSystem.getVersion()` | `0x0300` |
| Reader | USB contactless (NFC) only |

The ISD key was identified by sending INITIALIZE UPDATE and checking the card cryptogram on the host
against each candidate key, without sending EXTERNAL AUTHENTICATE, so no authentication try was spent.

## Probe (`probe/`, v3)

`00 02` (RUN_ALL), verbatim:

```
10 00 02 01 01 00 03   11 00 00 04 00 00 00   12 00 00 04 00 00 00   12 01 02 02 01 00 01
20 00 02 03 01 00 01   20 01 00 04 00 00 00   20 02 02 03 01 00 01   20 03 02 03 01 00 02
30 00 00 04 00 00 00   40 00 02 03 01 00 02   40 01 02 03 01 00 01   40 02 00 04 00 00 00
```

| Row | Probe | Result |
|---|---|---|
| `10 00` | 256-bit RSA NOPAD inversion | allocate: CryptoException `NO_SUCH_ALGORITHM` |
| `11 00` | 512-bit RSA NOPAD (control) | pass |
| `12 00` | 512-bit RSA **private** key, modulus p zero-padded | **pass**, correct inverse |
| `12 01` | 512-bit RSA public key, modulus p zero-padded | set key: `ILLEGAL_VALUE` |
| `20 00` | Wei25519 PLAIN_XY, transient key, cofactor 8 | init: `ILLEGAL_VALUE` |
| `20 01` | Wei25519 PLAIN_XY, transient key, cofactor 1 | **pass**, expected point |
| `20 02` | Wei25519 PLAIN_XY, persistent key, cofactor 8 | init: `ILLEGAL_VALUE` |
| `20 03` | Wei25519 PLAIN_XY, cofactor never set | init: `UNINITIALIZED_KEY` |
| `30 00` | secp256k1 PLAIN_XY (control) | pass |
| `40 00` | PACE_GM on Wei25519, cofactor never set | init: `UNINITIALIZED_KEY` |
| `40 01` | PACE_GM on Wei25519, cofactor 8 | init: `ILLEGAL_VALUE` |
| `40 02` | PACE_GM on Wei25519, cofactor 1 | **pass**, expected S·G + G |

## Configuration that works (landed)

- **Inversion:** a 512-bit `TYPE_RSA_PRIVATE` key, modulus `0x00³² ‖ p`, exponent `p−2`, 64-byte
  block. This is JCMathLib's `RSA_RESIZE_MOD` setup for JCOP4 P71. Before this change, the fork
  could not install on this chip: the constructor allocated a 256-bit key.
- **Wei25519:** cofactor 1. `ALG_EC_SVDP_DH_PLAIN_XY` does not use the cofactor, so the output is
  unchanged.
- **PACE_GM** (hardware point addition) works with cofactor 1, so an on-card verify-after-sign
  costs about two native EC operations. It is not implemented yet.

Commits: `15ef48d` (Ed25519 configuration), `2da32f9` (Cash applet, below).

## Suite on the card

`./gradlew test` (target `card`): install, then every test against the chip.

- **KeycardTest: 25/25**, including `signEd25519Test`, `stellarSep0005Test` (the SEP-0005 vector
  reproduces on the card) and the BIP85 release gate: `bip85Test`, `bip85PublishedVectorsTest`,
  `bip85CrossCheckTest`, `bip85FromSeedTest` and `bip85RejectsTest`.
- **StellarM4Test: 1/1**. The card signs a real Stellar testnet transaction, and the signature
  verifies.
- `Ed25519ProbeTest` and `HwProbeTest` always run in the simulator. They test the simulator's
  primitives; the probe CAP covers the same ground on the card.

One cross-check run failed with `6D00`. The cause was a second process that selected the ISD
mid-test. The test passed when re-run alone.

Timings over NFC: `signEd25519Test` 49.9 s, `stellarSep0005Test` 23.3 s, `bip85CrossCheckTest`
18.6 s (whole tests, several secure-channel round trips each). Per-signature timing has not been
measured.

## Free memory

From probe INS `03`, which uses the uncapped `getAvailableMemory(short[], short, byte)`:

| State | Persistent | Transient reset | Transient deselect |
|---|---|---|---|
| As delivered (stock Keycard) + probe | 91,132 B | 2,646 B | 3,808 B |
| Probe only | 107,768 B | 3,222 B | 3,216 B |
| **Fork installed** (math, keycard, 4 applets) + probe | **84,868 B** | **94 B** | 2,592 B |

The fork occupies 22,900 B of persistent memory and 3,128 B of CLEAR_ON_RESET RAM. The probe's own
package is installed in every row, so removing it frees a little more persistent memory than shown.
**The binding constraint is CLEAR_ON_RESET RAM, not NVM:** 94 B remain, so any new on-card feature
must reuse existing transient buffers.

## Divergences from jcardsim

1. 256-bit RSA keys: jcardsim accepts them; the chip refuses them.
2. Wei25519 cofactor 8: jcardsim accepts it; the chip rejects it at `KeyAgreement.init`.
3. A zero-padded modulus on an RSA *public* key is rejected; on a private key it is accepted.
4. The chip has `ALG_EC_PACE_GM`; jcardsim does not.
5. Memory: jcardsim always reports 32767 B. On the card, the Cash applet's second Ed25519 instance
   did not fit the remaining transient RAM, and its install failed with `6F00`. The Cash applet is
   back to upstream (`2da32f9`). That signer also had no PIN and no secure channel.
6. The identity certificate is write-once (`6985` on a second store). jcardsim gives each test
   class a fresh card, so this never showed. Both test classes now accept `6985`.
7. Test harness: on the card target, JUnit test discovery failed with a `VerifyError`, because
   `-noverify` was only passed for the simulator. The build reported success with zero tests run.
   `StellarM4Test` was also hard-wired to jcardsim. Both fixed in `0d347f0`.
8. NFC coupling: the card works only in a narrow spot on the reader. Elsewhere it answers
   ATR/ATS, browns out on the first real command, and the reader resets (`READER_UNAVAILABLE`)
   every ~1.6 s. Use a contact reader for loads where possible.

## Note store on the card (2026-10-22)

The note store (`docs/NOTE_STORE.md`) installed as its own package (`A0000008040003`) ahead of the
Keycard package. The full suite then ran on the card: KeycardTest 25/25 and StellarM4Test 1/1 again,
and **NoteStoreTest 11/11**. The 4 skipped tests are simulator-only because they need a fresh card:
install parameters, reinstall survival, no duress PIN configured, and factory reset.

**Capacity on the card**, by filling the store at the default 248 blocks and 64 entries. It matches
the simulator exactly:

| Pairs | 2 | 3 | 4 | 10 | 24 |
|---|---|---|---|---|---|
| Note size | 1,272 B | 1,562 B | 1,852 B | 3,592 B | 7,652 B |
| Notes | 49 | 35 | 31 | 16 | 8 |

**Memory**, from probe INS `03`, with the probe installed in both rows:

| State | Persistent | Transient reset | Transient deselect |
|---|---|---|---|
| Fork + probe (before) | 84,868 B | 94 B | 2,592 B |
| Fork + note store + probe | **13,548 B** | **88 B** | 2,592 B |

The store takes 71,320 B: 67,504 B of pool, chain table and directory, plus about 3.8 KB of package
code and object overhead. It takes 6 B of CLEAR_ON_RESET RAM, not the 0 B the design estimated. That
is consistent with the per-instance cost of one more applet, which the store applet code does not
allocate itself. Removing the probe frees a few more KB of NVM.

**Speed over this NFC link:** the capacity fill wrote 139 notes (293 KB) in 665 s, about **440 B/s**
end to end. That includes BEGIN, the 240-byte WRITE chunks through SC V2, and the COMMIT hash. So a
typical 3–4 pair receive takes roughly 3.5–4.5 s, and the `roundTrip` test (store a 3-pair note, then
read it back, LIST and STATUS) took 7.8 s. That is slower than the ~1 s estimate in
`SHELL_KENTER.md` §6.3. Where the time goes (NFC framing, AES-CCM, NVM writes) has not been
measured, nor has a contact reader.

## Duress PIN changes on the card (2026-10-22, 23500b6)

The store package was reinstalled because its interface changed (`-Pim.status.keycard.notes.reinstall=true`),
then the fork was reinstalled. The full suite then ran on the card:

| Suite | Result | Notes |
|---|---|---|
| KeycardTest | 26/26 | Includes `ed25519DuressTreeTest`: the duress PIN derives decoy Ed25519 keys, and the main PIN still reproduces SEP-0005 |
| StellarM4Test | 1/1 | |
| NoteStoreTest | 12/12 on the card | Includes `duressHides` and `duressShare`. The 6 tests that need a fresh card are simulator-only and passed there |

The PIN rules introduced in the same change are simulator-only tests: duress-assisted brute force,
INIT and CHANGE PIN equality, and factory reset.

**Capacity on the card**, main tree at 217 blocks / 56 entries, matches the simulator exactly:

| Pairs | 2 | 3 | 4 | 10 | 24 |
|---|---|---|---|---|---|
| Notes | 43 | 31 | 27 | 14 | 7 |

**Memory** (probe INS `03`): 12,924 B persistent, 86 B CLEAR_ON_RESET and 2,592 B CLEAR_ON_DESELECT
free. That is 624 B and 2 B less than before, the cost of the added code and the Ed25519 decoy chain
code.
