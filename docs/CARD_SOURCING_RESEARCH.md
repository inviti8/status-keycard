# Kenter card sourcing — synthesis of collected research (2026-07-14)

Synthesized entirely from material already fetched in session 0a1686f6 (no new web fetches):
Futako J3R452 product page, CardLogix JCOP4 P71 page, Satochip-DIY readme,
Tongxin THD89 Security Target (Lite), JCAlgTest results table.

## Headline findings

### 1. New capacity ceiling for retail cards: NXP J3R452 (JCOP 4.5, P71D600) — 450 KB flash
- SmartMX3 P71D600, 40 nm, 450 KB flash, 12.3 KB RAM
- JavaCard 3.0.5 Classic, GlobalPlatform 2.3, T=1 + T=CL, SCP02, state INITIALIZED (ISD usable)
- ECC 128–521 bit, **Ed25519 (RFC 8032) and Curve25519/448 (RFC 7748)** — relevant if Kenter ever needs ed25519 on-card
- CC EAL6+, EMVCo, FIPS 140-3 L3
- Retail: Futako Co. Ltd, Taipei — US$12/pc, MOQ 5 (online ordering closed; quote by email contact@futako.net)
- Raises the previously assumed retail ceiling (J3R180/J3R200 ≈ 169 KB usable). At ~450 KB flash,
  usable applet/data space plausibly ~350–400 KB → roughly 2–2.5× prior token-count estimate
  (~150–200 tokens vs ~60–80). Still far from the megabyte-class goal, but a real interim step.

### 2. Keycard-applet compatibility of the P71 SECID family is confirmed by data, not inference
JCAlgTest, J3R110 (same JCOP4 SECID platform as J3R180):
- `ALG_EC_SVDP_DH_PLAIN` / `ALG_EC_SVDP_DH_PLAIN_XY` : yes
- `ALG_ECDSA_SHA_256` : yes
- `TYPE_EC_FP_PRIVATE` at 128/160/192/224/**256**/384/521 : yes; transient EC private keys : yes
Satochip-DIY confirms J3R110 and J3R180 (recommended) work in practice with a secp256k1
wallet applet — i.e. custom-curve secp256k1 over EC_FP_256 works on this platform.
Checklist item (1) secp256k1: **PASS** for JCOP4 SECID (J3Rxxx SECID variants; EMV variants do NOT work).

### 3. Voltage/protocol checklist items answered for NXP P71
- Contact interface: continuous operation **1.62 V – 5.5 V** (covers 3 V class B), T=1 default, T=0 also
- NVM: **500 k cycle endurance minimum, 25-year retention** (CardLogix JCOP4 spec sheet)
Checklist items (3) and (4): **PASS** for P71-based cards.

### 4. THD89 (Tongxin) — the mainland producer path — is real but riskier
- Security Target: **TMCOS 4.0 on THD89 1.0.3**, JavaCard **3.1.0**, GP 2.3 + Amendments A/D/E/F,
  CC certified (doc rev 2025-01-22). This is the platform behind THETAKey T101/T104 retail cards.
- JCAlgTest, THD89 T101: EC_FP_256 yes, `ALG_EC_SVDP_DH_PLAIN_XY` yes, **but every
  `ALG_ECDSA_SHA_*` test aborted with `SystemException_NO_TRANSIENT_SPACE`**, and
  `ALG_EC_SVDP_DHC_PLAIN` : no. The retail T101 exposes very little transient RAM to applets.
- Matches Satochip-DIY's field report: THD89 cards "don't work reliably with official builds";
  they maintain tweaked applet builds for THD89.
- Implication: a THD89-based product is viable **only via a producer relationship** where the TMCOS
  configuration (transient memory quota, curve support) is negotiated — exactly the HK/mainland
  producer conversation planned. Bring the transient-space question to Tongxin/card makers directly.

### 5. Procurement hygiene (Satochip-DIY)
- Buy SECID variants, never EMV variants of the same part number (J3R150 exists as both).
- Cards must arrive with known/default ISD keys; a card that answers "Card cryptogram invalid!"
  is vendor-locked — do not retry (3 tries bricks the ISD). Aligns with checklist item (2).
- Lock cards with your own SCP key after loading the applet.

## Updated card ladder for Kenter on-card custody
| Tier | Card | Usable NVM | Status |
|---|---|---|---|
| Today, retail | J3R180 SECID | ~169 KB | Proven (Satochip-recommended), ~$8–12 |
| Today, retail | **J3R452 (JCOP 4.5)** | ~400 KB | Best capacity found; verify Keycard applet on JCOP 4.5 (JC 3.0.5 — should port cleanly) |
| Producer deal | THD89 / TMCOS custom config | TBD (ask) | Needs negotiated transient-RAM + curve config; JC 3.1 is a plus |
| Producer deal | eUICC-grade SE (1–2 MB) | 1–2 MB | The actual goal; not available retail anywhere in collected data |

## Open items (would need new research)
- J3H145 page fetch failed (0 bytes) — JCOP3 P60 145 KB, superseded by J3R anyway.
- No pricing/contact collected yet for Goldpac, Eastcompeace, Watchdata, FEITIAN, HuaDa.
- Whether JCOP 4.5 (J3R452) SECID feature set includes everything the Keycard applet uses —
  needs a $60 MOQ-5 sample order or a JCAlgTest run on an actual card.
