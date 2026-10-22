# Hardware probe

A small, standalone Java Card applet that checks whether a card supports the two primitives the
software Ed25519 core (`src/main/java/im/status/keycard/Ed25519.java`) depends on and AlgTest does
not cover:

1. a **256-bit** `TYPE_RSA_PUBLIC` key with `ALG_RSA_NOPAD` (used for modular inversion mod 2^255-19)
2. `ALG_EC_SVDP_DH_PLAIN_XY` on a **custom** curve (Wei25519, cofactor 8)

It also runs two controls (512-bit RSA NOPAD, and secp256k1 scalar multiplication), so a card that
rejects everything can be told apart from one that rejects only the primitives under test. Every
probe checks its own result against an embedded expected value.

It also probes the fallbacks, so one run answers what to do if a primary check fails:

- the same inversion on a **512-bit** key with a zero-padded modulus, which is how JCMathLib runs
  it on JCOP4 P71
- Wei25519 with the cofactor **never set** (JCMathLib's JCOP4 P71 configuration)
- `ALG_EC_PACE_GM` on Wei25519, which is hardware point addition (S·G + H), as needed for a cheap
  on-card verify-after-sign

The CAP targets Java Card 3.0.4, has no dependencies, and allocates nothing at install. It should
always install, even on a card that refuses a key size.

## Build

    ./gradlew probeCap      # -> build/probe/cap/im/status/keycard/probe/javacard/probe.cap
    ./gradlew test -Pim.status.keycard.test.target=simulator --tests im.status.keycard.probe.HwProbeTest

Package AID `F04B4350524F4245`, applet AID `F04B4350524F424501`.

## Run (GlobalPlatformPro)

    gp --install probe.cap
    gp -d --apdu 00A4040009F04B4350524F424501 --apdu 0003000000 --apdu 0002000000
    gp --uninstall probe.cap

`00 02 00 00 00` runs every probe and returns twelve 7-byte rows. Each probe can also be run on
its own to get its full output:

| APDU             | Probe                                                               |
|------------------|---------------------------------------------------------------------|
| `00 01 00 00 00` | info: `JCSystem.getVersion()` (2 bytes) + probe version (`03`)      |
| `00 03 00 00 00` | free memory, 3 × 4-byte ints: persistent, transient reset, transient deselect. Send it before `00 02`, which allocates |
| `00 10 00 00 00` | 256-bit RSA NOPAD, modulus 2^255-19, exponent p-2                   |
| `00 11 00 00 00` | control: 512-bit RSA NOPAD                                          |
| `00 12 00 00 00` | fallback: 512-bit RSA **private** key, modulus p zero-padded to 64 bytes |
| `00 12 01 00 00` | fallback: same, 512-bit RSA public key                              |
| `00 20 00 00 00` | Wei25519, transient (CLEAR_ON_DESELECT) key, cofactor 8             |
| `00 20 01 00 00` | Wei25519, transient key, cofactor 1                                 |
| `00 20 02 00 00` | Wei25519, persistent key, cofactor 8                                |
| `00 20 03 00 00` | Wei25519, transient key, cofactor never set                         |
| `00 30 00 00 00` | control: secp256k1                                                  |
| `00 40 00 00 00` | `ALG_EC_PACE_GM` on Wei25519, cofactor never set                    |
| `00 40 01 00 00` | `ALG_EC_PACE_GM` on Wei25519, cofactor 8                            |
| `00 40 02 00 00` | `ALG_EC_PACE_GM` on Wei25519, cofactor 1                            |

Every probe answers SW `9000`.

## Reading the result

Single probe: `[status][stage][excType][reason:2][outLen][out...]`
Summary row:  `[ins][p1][status][stage][excType][reason:2]`

| Field   | Values |
|---------|--------|
| status  | `00` PASS, `01` wrong result (computed, but not the expected value), `02` exception |
| stage   | `01` allocate (`getInstance`/`buildKey`), `02` set key or curve, `03` init, `04` compute |
| excType | `00` none, `01` CryptoException, `02` SystemException, `03` other |
| reason  | the exception's reason code, e.g. CryptoException `0001` ILLEGAL_VALUE, `0003` NO_SUCH_ALGORITHM |

A fully passing card returns, for `00 02 00 00 00`:

    10 00 00 04 00 00 00   11 00 00 04 00 00 00   12 00 00 04 00 00 00   12 01 00 04 00 00 00
    20 00 00 04 00 00 00   20 01 00 04 00 00 00   20 02 00 04 00 00 00   20 03 00 04 00 00 00
    30 00 00 04 00 00 00   40 00 00 04 00 00 00   40 01 00 04 00 00 00   40 02 00 04 00 00 00
    90 00

The 512-bit inversion check matches the value, not the length. A card returning fewer than 64 bytes
still passes, and the length is visible in `outLen` when the probe is run on its own.

The simulator (jcardsim) has no `ALG_EC_PACE_GM`, so there all three `40` rows read
`02 01 01 00 03` (CryptoException NO_SUCH_ALGORITHM at allocation). Their expected value is
cross-checked against BouncyCastle in `HwProbeTest`.
