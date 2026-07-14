# Producing cards from this fork

This applet is a fork of `keycard-tech/status-keycard`, licensed **Apache 2.0**. That license
permits commercial use, modification, and distribution without permission from or coordination with
the upstream project. You do **not** need the fork merged upstream to ship it: you build your own
CAP and install it on cards whose GlobalPlatform keys you control. `GridPlus/safe-card` and Cryptnox
are existing commercial forks of this same applet on their own cards — the model is proven.

## Why retail cards can't be reflashed (and why that doesn't matter)

Every JavaCard has GlobalPlatform **Issuer Security Domain (ISD) keys** that gate installing and
deleting applets. Installing a CAP requires authenticating to the ISD.

- A **retail** card (e.g. a consumer keycard.tech card) has its ISD keys **rotated to secret values
  and locked** at personalization — deliberately, so nobody can push a new applet onto a user's
  card. Those keys are not published, and each failed GP auth burns one of a small retry counter
  (typically 3–10) before the card bricks **permanently**. Do not attempt GP auth against a retail
  card. This is a property of *that card's personalization*, not of the chip or the ecosystem.
- A **blank** card ships with the **well-known default ISD keys** (`404142…4F`, occasionally a
  vendor default). You can authenticate, install, personalize, then rotate the ISD keys to your own
  secret values and lock them — at which point *your* cards are the locked cards.

So "we need a dev card" really means "we need cards whose ISD keys we control," which is every blank
card before you lock it. Users never install anything; they receive a finished card.

## Sourcing cards

The chips under keycard.tech / Cryptnox cards are standard **NXP JCOP** parts (J3R200 = JCOP4 P71,
J3R452 = JCOP4.5), sold openly by card distributors. There is no reason to pay a keycard vendor's
markup for what is, functionally, a blank NXP card with default keys plus a fitting form factor.
Buy blank JavaCards directly:

- **NXP JCOP distributors:** MoTechno (EU, business accounts, volume discounts), AFT (India),
  CardLogix, Smartcard Focus, and similar.
- **What to order:** blank **JCOP4 / JCOP4.5** cards (J3R200 or J3R452) with **default GP keys** and
  the desired form factor (ID-1 card, NFC, or SIM/plug for embedded).

**Verify before bulk buying** (this is the one place "any wholesaler" bites back):

1. **Default/known GP keys** — some resellers pre-personalize or lock cards; confirm the listing
   states default GP keys, and validate with a *single* `gp --info` (unauthenticated, safe) plus one
   authenticated `gp --list` with the default key on a sample. If GP auth fails, stop — do not retry.
2. **Correct chip + JavaCard version** — this applet targets JavaCard 3.0.5 (JCOP4/4.5). Confirm the
   ATR/CPLC identifies a JCOP4-class NXP part.
3. **Required algorithms present** — the Ed25519 path needs `KeyAgreement.ALG_EC_SVDP_DH_PLAIN_XY`,
   `Cipher.ALG_RSA_NOPAD` with a 256-bit public key, SHA-512, and enough EEPROM. Run the applet on a
   sample and exercise a SIGN before committing to a card model.
4. **Buy 1–2 samples first, always.** See GATE-0 below.

## GATE-0: which chip + crypto core

The Ed25519 implementation in this fork is **Core C** — software Ed25519 riding the native EC engine
over Wei25519 (see `ED25519.md`). It runs on **any** J3R200 or J3R452 today, with no NDA. Its one
caveat is side-channel hardness: the scalar arithmetic `S = k·s + r mod L` runs in software
(`BigNumberMath`), the same exposure class as the existing BIP-340 Schnorr path — acceptable for
many uses, but review before a high-assurance deployment.

Two stronger options exist and both hinge on a hardware question that a J3R452 sample must answer:

| Core | What | Gate |
|---|---|---|
| **A. Native EdDSA** | JavaCard 3.1 `SIG_CIPHER_EDDSA` / `buildXECKey` on J3R452 | Whether an ordinary CAP with default GP keys can call it, or whether it is NXP-proprietary / NDA-gated. **Unverified — this is GATE-0.** |
| **B. SecureBox** | NXP native-C sandbox implementing Ed25519 | NXP partner / NDA (Cryptnox ships crypto this way). |
| **C. Software (this fork)** | Wei25519 + `BigNumberMath`, as built | None. Works now. |

**GATE-0 action:** get a J3R452 sample and confirm with the distributor / NXP whether native EdDSA
is callable from a default-keyed CAP. That single answer decides cost (free vs NDA/partner) and the
production card model. Core C is the fallback that ships regardless.

## Production lifecycle per card

1. **Source** blank JCOP cards with default GP keys (above).
2. **Build** the CAP: `./gradlew convertJavacard` → `build/javacard/im/status/keycard/javacard/keycard.cap`.
3. **Install** over GlobalPlatform with the default key. The repo's `install` Gradle task does this
   (SELECT ISD → open secure channel → delete old instances → load the math package and the keycard
   package → install the four applets). For a standalone flow, GlobalPlatformPro works too:
   `gp --install keycard.cap` (defaulting to `404142…4F`).
4. **Personalize** at the applet level: INIT (PIN / PUK / pairing secret), then load or generate the
   key material. No GP/brick risk at this layer.
5. **Rotate and lock the GP ISD keys** to secret values you control (`gp --lock <newkey>`). From here
   the card only accepts *your* card-manager credentials — it is now a locked "retail" card. **Guard
   these keys as you would an HSM master key**; losing them means no card in the field can ever be
   updated, and a leak means anyone can reflash your fleet.
6. **Ship.** The user receives a finished card and installs nothing.

At volume this is a real provisioning operation (HSM-backed key custody, a personalization line,
serial/UID tracking), not just a build step — plan for it as manufacturing, not software.

## Testing without hardware

The full applet, including the Ed25519 path, runs in the bundled **jcardsim** simulator
(`./gradlew test -Pim.status.keycard.test.target=simulator`). Use this for functional development and
CI; use sampled real cards for the timing/EEPROM/algorithm-availability checks that a simulator
cannot make. See `ED25519.md` for the simulator caveats this fork carries.
