# Personalization tool with a card as the CA (plan)

**Status:** plan for owner review. No code yet. It builds on `docs/ON_CARD_IDENTITY.md`, which
covers on-card identity generation.

**Owner decision:** the production CA key lives on a spare card running this applet, used as the
HSM. A dedicated HSM can replace it later. The tool runs on an offline laptop with one operator,
the owner.

## Applet facts the tool relies on

Each of these was checked against `KeycardApplet.java` on `feat/stellar-ed25519`.

### SIGN (`80 C0`)

- **P1 = `01`:** derive from the master. The data is the 32-byte hash followed by the path
  (4 bytes per level).
- **P1 values the fork rejects** (`6B00`): `00` current key, `02` derive and make current, `03`
  PIN-less.
- **P2 = `00`:** ECDSA over secp256k1.
- **No further hashing:** the card signs the 32 bytes as a precomputed hash
  (`signPreComputedHash`). The tool therefore sends `SHA-256(target identity public key)`.
- **Low S:** the card normalises the signature itself (`Crypto.fixS`).
- **Needs** an open SC V2 and a verified PIN.
- **Response:** `A0 81 len { 80 41 <65-byte uncompressed public key> 30 … <DER (r,s)> }`. There is
  no `v`. The SDK's `RecoverableSignature(hash, response)` parses this and computes the recovery id
  against the returned public key, so the tool does not reimplement it. The SDK call is
  `KeycardCommandSet.signWithPath(hash, path, false)`.

### EXPORT KEY (`80 C2`)

- **P2 = `01`** returns only the public key, at any path, after VERIFY PIN.
- **Private keys can be exported only at EIP-1581 paths** (`m/43'/60'/1581'/…`), and the BIP85
  command only at `m/83696968'/…`.
- **The CA path must sit under neither prefix.** Otherwise anyone with the PIN could export the CA
  private key.

### Other facts

- **One seed, two trees:** the seed of a card loaded with LOAD KEY (seed) also defines its Ed25519
  tree. That's harmless for a CA card that is never used as a wallet, but it's one more reason the
  phrase must never be typed into any wallet.
- **Duress PIN:** INIT on this fork needs one (or defaults it to the PUK prefix). A duress PIN
  unlocks a decoy tree, so a CA card unlocked with it signs under a **different** key. The tool's
  key check (below) turns that into a refusal rather than a bad certificate.
- **CA cards must be certified too:** `KeycardApplet` refuses everything on an uncertified card, so
  a CA card needs a certificate to work at all. See "Certifying the CA cards themselves".

## The CA key

### Path

The path is fixed forever. Proposal: `m/1009'/0'/0'`. It is hardened all the way and sits under
neither the EIP-1581 nor the BIP85 prefix. Purpose `1009'` is not, to my knowledge, used by any
wallet standard; confirm before freezing it.

The tool hard-codes the path and refuses any other.

### Active and spare

The spare CA is a separate phrase on its own card pair, sealed, with the same path. A spare derived
from the active seed (same phrase, another index) would fall together with the active key when the
phrase is compromised, and compromise is the case the spare exists for.

Clients pin both public keys (the Kenter side is planned).

### Phrase

GENERATE MNEMONIC on the CA card (24 words). The laptop builds the seed and runs LOAD KEY on the CA
card, then on the backup card. The phrase crosses the offline laptop once, at setup.

- **Write it down:** two copies, on paper or metal, in two places. The phrase is the real CA
  secret; the cards are only convenient copies.
- **Why not GENERATE KEY:** it makes a seed nobody can back up, so a lost CA card would mean a new
  CA and re-pinning every client.

## Flows

### A. CA setup (once per CA, offline laptop)

1. **Install** the applet on the CA card and the backup card. Generate their identities and certify
   them with a **throwaway key** (see below). Pin both identity keys in the tool config.
2. **INIT** each card with the CA PIN, the PUK and a duress PIN. Use all-different values, and none
   reused from any wallet.
3. **GENERATE MNEMONIC** on the CA card. Show the phrase and record it.
4. **LOAD KEY (seed)** on both cards.
5. **EXPORT KEY** (P2 `01`, CA path) on both cards. Stop unless the two public keys are equal.
6. **Write the compressed CA public key to the tool config.** This is the key clients pin.
7. **Sign and verify a test hash** on both cards.
8. **Lock the ISD keys** of both CA cards.
9. Label the cards **"CA – NOT A WALLET"**. Store the backup card apart from the active one.

### B. Per customer card

There are two readers, chosen by PC/SC reader name in the config, or one reader with the cards
swapped. For each target card:

1. **Target: SELECT Ident.** If it is certified (98 bytes), stop and say so. If it is generated
   (33 bytes), resume with that key. If it is empty, send GENERATE IDENTITY. Read the CPLC through
   the ISD.
2. **Refuse a CA card as the target:** stop if the target's identity is one of the pinned CA-card
   identities.
3. **CA card:**
   - SELECT, and check its identity against the pinned CA-card identities.
   - Open SC V2 and VERIFY PIN.
   - **Key check:** EXPORT KEY (public, CA path) must equal the configured CA public key. A wrong
     card, a duress PIN or a wrong seed all fail here, before anything is signed.
4. **Log, then sign:** append a log entry first (`intent`: target identity public key, CPLC,
   time), then SIGN `SHA-256(pub)` at the CA path.
5. **Build the certificate:**
   - Parse the response with `RecoverableSignature`.
   - Check that the returned public key is the CA key.
   - Re-check that S is low.
   - Assemble `pub ‖ r ‖ s ‖ v` (98 bytes).
6. **Log, then store:** log `signed` with the certificate, then STORE DATA it to the target.
7. **Verify like the client:**
   - SELECT the Keycard applet on the target.
   - Check the certificate against the pinned CA keys.
   - Open SC V2, which checks the transcript signature under the certificate's key.
   - Then log `verified`.
8. **Lock** the target's ISD keys, then log `locked`.

After a drop at any step, rerun on the same card. The resume logic follows the identity state, and
the log shows how far the card got.

## Certifying the CA cards themselves

A CA card needs a certificate before the Keycard applet answers. Certify CA cards with a
**throwaway key** generated on the offline laptop and deleted right after. No client pins that
key, so **no wallet client ever accepts a CA card**, which makes the "not a wallet" rule hold in
software too.

The tool does not rely on that certificate. It pins the CA cards' **identity keys** directly. Do
not use the dev CA, whose key is public, or the production CA.

## The ceremony log

The CA card has no signature counter, so the log is the only record of what the CA signed.

**Format:**
- Append-only, one line per state change: `intent`, `signed`, `stored`, `verified`, `locked`.
- Each line carries the target identity public key, the CPLC, the batch and the time.
- Each line is flushed to disk before the tool takes the next step.

**Reconciliation, per batch:**
- Every `intent` must end in `locked`, or be explained (a rerun on the same identity, or a scrapped
  card).
- The number of `signed` lines must equal the number of cards shipped.

**Limit:** someone who controls the laptop and knows the PIN can sign without logging. The log
catches mistakes and makes an honest audit possible; it can't stop a malicious operator. That is
accepted for a single operator.

**Optional applet change, not proposed now:** a CA mode where SIGN increments a persistent on-card
counter and returns it in the response. Signatures then become countable on the card itself. Until
then, the tool could call the note store's NEXT INDEX before each SIGN and log the index. That
gives a monotonic number the laptop can't roll back. It is not enforced, because an attacker could
skip it, but it is cheap.

## Where the tool lives

- **Location:** this repo, `tools/personalize/`. It is a Java CLI on the same SDK, `apdu4j` and GP
  code as `InstallTask`. It contains nothing downstream-specific; pinned keys, reader names, the
  path and the log location come from a config file.
- **Downstream:** a wrapper can hold its own config.
- **ISD locking:** per-card keys derived from a master key (`gp --lock` style). That master key is
  a second secret. One option: derive it from the CA phrase via BIP85 on the CA card (a fixed index
  under `m/83696968'`), so the one phrase backs up everything. The cost is that the GP master
  crosses the laptop at every session.

## Owner decisions (2026-11-12)

1. **The CA path:** open; the owner asked for context.
2. **The spare CA:** a separate phrase on its own card pair. Yes.
3. **The GP master key:** not derived from the CA phrase. The owner wants to avoid extra
   complexity unless it is needed; the simplest adequate scheme is still open.
4. **Readers:** a contact reader for the CA card.
5. **The counter:** the tool logs a NEXT INDEX value before each SIGN. The CA-mode applet counter is
   left for later.
