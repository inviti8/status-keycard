# Hardware probe

A small, standalone Java Card applet that checks whether a card supports the two primitives the
software Ed25519 core (`src/main/java/im/status/keycard/Ed25519.java`) depends on and AlgTest does
not cover:

1. a **256-bit** `TYPE_RSA_PUBLIC` key with `ALG_RSA_NOPAD` (used for modular inversion mod 2^255-19)
2. `ALG_EC_SVDP_DH_PLAIN_XY` on a **custom** curve (Wei25519, cofactor 8)

It also runs two controls (512-bit RSA NOPAD, and secp256k1 scalar multiplication), so a card that
rejects everything can be told apart from one that rejects only the primitives under test. Every
probe checks its own result against an embedded expected value.

The CAP targets Java Card 3.0.4, has no dependencies, and allocates nothing at install. It should
always install, even on a card that refuses a key size.

## Build

    ./gradlew probeCap      # -> build/probe/cap/im/status/keycard/probe/javacard/probe.cap
    ./gradlew test -Pim.status.keycard.test.target=simulator --tests im.status.keycard.probe.HwProbeTest

Package AID `F04B4350524F4245`, applet AID `F04B4350524F424501`.

## Run (GlobalPlatformPro)

    gp --install probe.cap
    gp -d --apdu 00A4040009F04B4350524F424501 --apdu 0002000000
    gp --uninstall probe.cap

`00 02 00 00 00` runs every probe and returns six 7-byte rows. Each probe can also be run on its
own to get its full output:

| APDU             | Probe                                                          |
|------------------|----------------------------------------------------------------|
| `00 01 00 00 00` | info: `JCSystem.getVersion()` (2 bytes) + probe version        |
| `00 10 00 00 00` | 256-bit RSA NOPAD, modulus 2^255-19, exponent p-2              |
| `00 11 00 00 00` | control: 512-bit RSA NOPAD                                     |
| `00 20 00 00 00` | Wei25519, transient (CLEAR_ON_DESELECT) key, cofactor 8        |
| `00 20 01 00 00` | Wei25519, transient key, cofactor 1                            |
| `00 20 02 00 00` | Wei25519, persistent key, cofactor 8                           |
| `00 30 00 00 00` | control: secp256k1                                             |

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

    10 00 00 04 00 00 00   11 00 00 04 00 00 00   20 00 00 04 00 00 00
    20 01 00 04 00 00 00   20 02 00 04 00 00 00   30 00 00 04 00 00 00   90 00
