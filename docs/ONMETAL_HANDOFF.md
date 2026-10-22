# ONMETAL_HANDOFF.md — validating the Ed25519 fork on real cards

**Audience:** the agent working in this repo (`status-keycard`, JavaCard applet,
branch `feat/stellar-ed25519`).
**Written:** 2026-10-22, by the Kenter side, on the arrival of two development
cards.
**Status:** a brief, not a design. Everything here is already decided elsewhere;
this says what to do with the hardware and what to send back.

---

## 0. One paragraph

Two **NXP J3R200** development cards arrived. Everything in this fork has only
ever run in **jcardsim**, which is permissive in two specific ways that real
silicon may not be. Your job is to find out whether the Ed25519 core actually
runs on a chip, using the probe applet that was written for exactly this, then
run the existing suite on metal. One measurement Kenter needs from you is not
pass/fail at all — see §5.

---

## 1. What the cards are, and what that settles

| | |
|---|---|
| Part | **NXP J3R200** — JCOP 4, SmartMX3 P71 |
| JavaCard | **3.0.5 Classic** (not 3.1) |
| Usable NVM | ~169 KB |
| GP | 2.3, SCP02, default ISD keys |
| Reader | a PC/SC reader is already on hand and working (`KEYCARD.md`, empirical section) |

Two consequences, both good:

**GATE-0 is not your problem on these cards.** GATE-0 asks whether a retail
**J3R452** exposes native `SIG_CIPHER_EDDSA` to an ordinary CAP. A 3.0.5 card
never will, so a J3R200 cannot answer it and does not need to. Do not spend
time on it.

**Core C does not need GATE-0 anyway.** `docs/PRODUCTION.md`: the core in this
fork is software Ed25519 over Wei25519, and it *"runs on **any** J3R200 or
J3R452 today, with no NDA."* These cards are the intended target. What is
unverified is only whether the chip permits the primitives jcardsim permitted.

---

## 2. Two hard cautions

**Never run `./gradlew lock`.** `build.gradle` marks it
`//DESTRUCTIVE: Running this task will lock you out of updating the applet!`
It rotates the GP ISD keys to values you then have to manage. On a development
card that permanently burns one of the two.

**Keep the second card pristine** until a full install → probe → test cycle has
succeeded on the first. With two cards and no spares, a GP mishap on your only
working one stops the workstream until more arrive.

---

## 3. Do the probe before the applet

`probe/src/im/status/keycard/probe/HwProbeApplet.java` is dependency-free and
**allocates nothing at install time**, so it installs even where a key size is
refused — a refusal comes back as a result record rather than a dead applet.
The full fork does the opposite: `new Ed25519()` runs in the `KeycardApplet`
constructor and allocates the 256-bit RSA key, so **a card that refuses that
size fails to install the whole applet** (`KEYCARD.md` R0 flags this). Probing
first is what keeps a refusal legible instead of looking like a broken build.

```sh
./gradlew probeCap                       # → build/probe/cap/.../probe.cap
gp --install build/probe/cap/.../probe.cap
# SELECT F04B4350524F4245 then INS 0x02 — runs everything, one 7-byte row per probe
```

### What each row means

| INS | Tests | If it fails |
|---|---|---|
| **0x10** | 256-bit RSA public key + `ALG_RSA_NOPAD`, modulus `2²⁵⁵−19` — modular inversion | **Most likely failure.** Try **0x12** |
| **0x12** | The same inversion with the modulus zero-padded to 512 bits — how JCMathLib does it on JCOP4 P71 (`RSA_RESIZE_MOD`). P1 selects private/public key | A pass here means a **config change**, not a redesign |
| **0x11** | Control: 512-bit RSA + `ALG_RSA_NOPAD`, a size AlgTest reports as supported | If *this* fails, the problem is `ALG_RSA_NOPAD` itself, not the key size |
| **0x20** | `ALG_EC_SVDP_DH_PLAIN_XY` on Wei25519. P1: `00` transient+cofactor 8 (**what `Ed25519.java` uses**), `01` cofactor 1, `02` persistent, `03` cofactor never set (JCMathLib's P71 config) | Try the variants in that order; `03` is the known-good config elsewhere |
| **0x30** | Control: the same on secp256k1, which stock Keycard proves works | If `0x20` fails and `0x30` passes, it is the **curve parameters**, not the algorithm |
| **0x40** | `ALG_EC_PACE_GM` on Wei25519 — hardware point addition | Optional. It would buy a cheap on-card verify-after-sign; its absence is not a blocker |
| **0x01** | `JCSystem.getVersion()` + probe version | Record it in the report |

Record **every** row, including passes. "0x10 failed, 0x12 passed" is a
different outcome from "both failed" and they lead to different work.

---

## 4. Then the suite, on metal

`testTarget` already defaults to `'card'` and `test` depends on `install`, so
with a card in the reader:

```sh
./gradlew test
```

installs the fork and runs the whole suite against the chip — including
`StellarM4Test`, the end-to-end Stellar transaction signing that has only ever
run in the simulator, and the `bip85*Test` family that `docs/STELLAR_ED25519_FORK.md`
§7 names as a **release gate**: *"run them against the first real personalized
card."* That gate is now runnable, and it is the headline result.

Dev environment, from `STELLAR_ED25519_FORK.md` §9: JDK 11 (not 17),
`GRADLE_USER_HOME=D:\gradle-home`, and run `.ps1` files rather than inline
PowerShell.

---

## 5. The measurement Kenter actually needs

**Free NVM on a J3R200 after the fork is installed.**

This is not pass/fail and it is not in any test. It decides a product question
on the Kenter side and nobody has the number.

Kenter's Model 2 ("the card is the wallet") stores note bytes on-card at a
budget of ~1.5 KB per note. `SHELL_KENTER.md` §6.2 estimates **~60–80 notes**
on a J3R200-class card — but that figure is *free NVM after the applet*, and it
was written for a stock-sized applet. This fork carries JCMathLib,
`BigNumberMath` and Wei25519, and is substantially larger. If the fork leaves
little room, a signing card and a custody card cannot be the same card, and
Kenter's card tier is shaped differently.

So: after `./gradlew test` succeeds, report **free persistent memory**
(`JCSystem.getAvailableMemory(MEMORY_TYPE_PERSISTENT)` or the GP equivalent),
before and after install if you can get both.

---

## 6. What to send back

A short report, in this repo, covering:

1. **Probe rows** — all of them, verbatim, with the card's JavaCard version.
2. **Which Core C configuration works**, if the default did not: the inversion
   variant (0x10 vs 0x12/P1) and the ECDH variant (0x20/P1). If a non-default
   config is needed, land the change on the branch and say so.
3. **Suite result on metal**, with `StellarM4Test` and the BIP85 gate called out
   by name.
4. **Free NVM after install** (§5).
5. **Anything that differed from jcardsim**, however small. Divergences between
   simulator and silicon are the whole reason this exercise exists, and a
   surprise that nobody wrote down is one somebody rediscovers later.

Then update `docs/PRODUCTION.md`'s GATE-0 table: Core C moves from *"runs
today"* (an inference from the datasheet) to *"verified on J3R200 on
2026-10-xx"*, or to whatever the truth turns out to be.

---

## 7. What is explicitly not yours

- **GATE-0 / native EdDSA** — needs a J3R452; not answerable here (§1).
- **The on-card token store** (`SHELL_KENTER.md` §6.3 asks this repo to specify
  the APDUs first). Real work, and it waits on §5's number, since there is no
  point specifying a slot pool before knowing how many slots fit.
- **Anything in the `kenter` or `keycard-shell` repos.** If the probe forces a
  change to the signing path, say so in the report and the Kenter side will
  follow it; do not reach across.

## 8. Background, if you want it

- `docs/ED25519.md` — the Core C design
- `docs/PRODUCTION.md` — GATE-0, card sourcing, the production lifecycle
- `docs/STELLAR_ED25519_FORK.md` — what the fork changed, §7 release gates, §9 dev env
- `docs/CARD_SOURCING_RESEARCH.md` — the J3R200 / J3R452 capacity ladder
- Kenter's `KEYCARD.md` R0 and R3 — why installing the fork can fail on a card
  that refuses the 256-bit key, and the keyring-vs-note-custody split
