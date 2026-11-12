# On-card identity key generation (plan)

**Status:** approved by the owner (§7). Implemented in the simulator: `IdentApplet`, `SharedMemory`,
`TestIdentity.provision`, and `IdentityTest` 8/8; full simulator suite 73/73; the CAP converts.
Not yet run on a card. **Branch:** `feat/stellar-ed25519`.

## The problem

The identity key authenticates the card. SC V2 signs every channel-open transcript with it
(`SecureChannelV2.openSecureChannel`, step 6). A client trusts the key only if the certificate in
SELECT (`8A`) recovers to a CA public key the client has pinned.

Today the personalization host creates that key. `IdentApplet.processStoreData` takes one plain
STORE DATA of `CERT_LEN + KEY_SECRET_SIZE` = 98 + 32 bytes. Those bytes are the certificate followed
by the identity private scalar. The applet calls `SharedMemory.idPrivate.setS(...)` and sets
`idCert[0] = CERT_VALID` (write-once). On the test side, `TestIdentity.certStoreData` builds this
payload with the SDK (`Certificate.createCertificate` → `toStoreData`). That code reads the private
key's `getD()`.

So every card's identity private key exists, at least briefly, on the personalization host. Anyone
who compromises that host can clone a certified identity, and so can any copy of its output: logs,
backups, a script's temp file. A clone passes the counterfeit check that CA pinning exists to make.
The check is only as strong as the most careless copy of the host's output.

## Goal

1. The card generates its identity keypair internally and exports only the public key.
2. The CA signs the public key off-card, on an offline HSM.
3. The host writes back only the 98-byte certificate.
4. The private key never leaves the card.

Keep these properties:
- The identity survives FACTORY RESET and changes only when the applet is reinstalled.
- The 98-byte certificate format and the SELECT response stay as they are.
- Personalization completes while the ISD keys are still the defaults.

## 1. APDU design and state machine

Everything stays in the Ident applet, in plain APDUs. SC V2 cannot carry them, because the channel
needs the identity that is being created.

### State

The state is kept in `SharedMemory.idCert[0]`, which already holds the flag:

| Value | State | `idCert[1..33]` | `idCert[34..98]` | Identity key |
|---|---|---|---|---|
| `0x00` | EMPTY | — | — | none |
| `0x55` | GENERATED | compressed public key | — | on card, uncertified |
| `0xAA` | CERTIFIED (frozen) | compressed public key | CA signature `r‖s‖v` | on card, certified |

`0xAA` keeps today's meaning. `KeycardApplet.process` refuses every command unless the state is
`0xAA` (line 259), and that stays as it is. An uncertified card does nothing, so it fails closed.

### GENERATE IDENTITY

Proposal: `80 16 00 00`, no data. `0x16` sits next to the removed IDENTIFY CARD `0x14`.

- **CERTIFIED** → `6985`.
- **EMPTY or GENERATED:**
  1. Write `idCert[0] = 0x00` first. It is a single-byte write, so it is atomic.
  2. Call `KeyPair.genKeyPair()` on the persistent `(idPublic, idPrivate)` pair.
  3. Compress `idPublic.getW()` in the APDU buffer: `02`/`03` by the parity of Y, then X.
  4. In one transaction, copy the 33 bytes to `idCert[1..33]` and set `0x55`.

  Clearing the flag before step 2 matters. A tear during key generation must not leave GENERATED
  pointing at a public key that no longer matches the private key. A torn GENERATE leaves EMPTY, and
  the host just sends GENERATE again.
- **Response:** the 33-byte compressed public key, `9000`.

### STORE DATA (`80 E2 00 00`), changed

- **CERTIFIED** → `6985` (unchanged).
- **EMPTY** → `6985`: nothing has been generated to certify.
- **Lc ≠ 98** → `6A80`. The old 130-byte form, certificate plus private key, is refused, so an old
  personalization script fails instead of injecting a key.
- **`cert[0..33]` ≠ `idCert[1..33]`** → `6A80`. The certificate must name the key this card holds.
- **Otherwise:** in one transaction, copy `cert[33..98]` to `idCert[34..98]` and set `0xAA`.

The applet does not verify the CA signature. It has no CA key to verify against, and recovery
always succeeds for some key. The client is the verifier, and step 3 of the flow runs that exact
check.

### SELECT on the Ident applet

- **CERTIFIED:** returns the 98-byte certificate (unchanged).
- **GENERATED:** returns the 33-byte public key. The two lengths tell the states apart. This lets a
  host that dropped the link after GENERATE resume without generating again. Generating again would
  strand a signature the HSM has already made.
- **EMPTY:** returns no data (unchanged).

### If certification never arrives

The card stays GENERATED (or EMPTY). The Keycard applet refuses all commands, and the host can send
GENERATE again at any time. Recovery is either a later STORE DATA or a reinstall. No state is worse
than "uncertified card that does nothing".

## 2. Who can generate or replace the identity

| Attacker holds | Before certification | After certification |
|---|---|---|
| The card only | Can send GENERATE again. The result is an uncertified card that does nothing. Can't get it certified without the CA. If they do it mid-ceremony, the host's STORE DATA fails the public-key match (`6A80`), so it fails closed. | GENERATE and STORE are refused (`6985`). No command leaves CERTIFIED. |
| Card + ISD keys | Same as above. | Can delete and reinstall the package. That destroys the identity, which lives in the package's static fields, and wipes the Keycard state. The result is a new **EMPTY** identity that no pinned CA has signed, so clients reject it. |
| The personalization host | Sees only public keys and certificates. Nothing on it can clone a card, even after the fact. | Same. |
| The CA HSM, or a host driving it | Can sign a public key the attacker generated, which mints a counterfeit identity. | Same. This is the residual risk (below). |

So **identity integrity does not depend on locking the ISD.** Holding the ISD keys gives the power
to wipe a card or replace its code. Replaced code comes with a new, uncertified identity, and the
certificate check catches it. Locking the ISD still matters for other reasons (denial of service,
code substitution on cards that never get checked), so step 4 of the flow stays as planned.

**Overwriting the wallet keeps the identity.** A holder who knows the PIN erases a wallet with
VERIFY PIN, then FACTORY RESET. If PIN and PUK are both blocked, the PIN isn't needed. They then
re-provision with INIT, then GENERATE MNEMONIC and LOAD KEY (seed), or LOAD KEY with a restored
seed. None of these commands touches `idCert` or `idPrivate`, today or under this plan, so the
erased card keeps its certified identity. The client accepts it with no CA involvement. The client
checked here never reinstalls the applet in the field.

Only a GlobalPlatform reinstall loses the identity. That is developer, support or RMA work, and the
card comes back EMPTY. It can generate a new key but needs our CA ceremony to be accepted again. A
reinstall by anyone else therefore turns the card into one clients reject, which is the intended
outcome.

**Gating GENERATE to the ISD secure channel** was considered and is not recommended. The applet would
take personalization only through `INSTALL [for personalization]` under SCP02 and check
`GPSystem.getSecureChannel()`. Costs:
- the GlobalPlatform API export files (not in the Oracle kit), and
- weaker jcardsim coverage.

It protects nothing the certificate check doesn't, because the CA is the real gate. This is listed
as an owner question in case a defence-in-depth argument wins.

**Residual risk: the CA signs whatever it is shown.** On-card generation removes the passive,
retroactive cloning path. It doesn't stop an active attacker who can get a public key in front of the
HSM during a ceremony. The controls belong to the ceremony, not the applet:
- An offline host.
- An HSM PIN held by a person who is not the operator (two-person rule if available).
- A ceremony log: identity public key, CPLC serial, batch, time.
- Signatures reconciled against cards per batch.

The client's revocation tools are a denylist of identity public keys, and moving to the sealed spare
CA.

## 3. Key generation on JCOP4 P71

- `KeyPair(ALG_EC_FP, 256)` with the secp256k1 parameters (`SECP256k1.setCurveParameters` on both
  halves), then `genKeyPair()`. **This exact sequence already runs on the J3R200:** `CashApplet`'s
  constructor uses it (`CashApplet.java:46-51`), and the Cash applet installs on metal
  (`ONMETAL_REPORT.md`, `2da32f9` onward). The new step runs at personalization time rather than at
  install, which makes no difference to the API.
- The constructor builds `idPublic` as a persistent `ECPublicKey`. It then forms
  `new KeyPair(idPublic, SharedMemory.idPrivate)` so `idPrivate` stays the key SC V2 signs with.
  - **Cost:** one persistent public-key object, roughly 100–200 B of NVM out of 12,504 B free.
  - **No CLEAR_ON_RESET RAM.** Only 86 B are left; compression works in the APDU buffer.
- The OS draws the scalar from the chip's RNG and keeps it in [1, n−1], so the applet needs no range
  check.
- **The 512-bit RSA inversion workaround is not involved.** It belongs to Ed25519 (Edwards
  conversion) and is untouched. The same goes for Wei25519 cofactor 1. The identity is plain
  secp256k1, which the chip supports natively.
- **To measure on metal:** `genKeyPair` time (expected to be well under a second) and free NVM after
  the change.

## 4. Should the certificate bind more than the public key?

**Recommendation: no. Keep the 98 bytes.**

Today's certificate signs `SHA-256(compressed public key)` (SDK `Certificate.createCertificate`,
`NONEwithECDSA` over the digest), with `v` for recovery.

**What binding a serial or batch id would buy:**
- Revoking a batch without a list of keys.
- Tying the identity to the CPLC.

**What it costs:**
- The applet's `CERT_LEN` and SELECT template.
- The upstream SDK's `Certificate` parser (fork it or write our own).
- The client parser and recovery input.
- SimServer and every test helper.
- Upstream format compatibility.

The serial would only be a label in any case. The client can't check a CPLC it reads over NFC
against anything trustworthy. The ceremony log already maps public key → serial → batch, so a batch
can be revoked by denylisting its keys.

**A cheaper variant:** a domain-separated digest, `SHA-256("<label>" ‖ pubkey)`. It keeps 98 bytes
but changes what the client hashes before recovery. It only matters if the CA key ever signs
anything else. A dedicated CA key that never does gets the same result with no format change. Owner
question.

**Host hygiene:** the HSM returns DER `(r, s)`, and `s` can be high. Normalise to low-S (`s = n − s`
if `s > n/2`) and compute `v` against the normalised pair. The client checked here verifies against
its pinned CA keys after normalising `s` and does not use `v`, so it accepts either form. Clients that
recover the CA from `v`, like the upstream SDK, or that enforce low-S need the normalised form, and
normalising costs nothing. The SDK's own `createCertificate` does not normalise.

## 5. Test plan

### Applet tests (simulator), new `IdentityTest`

1. EMPTY: SELECT returns no data; STORE DATA → `6985`; the Keycard applet refuses OPEN SC (`6985`).
2. GENERATE returns a 33-byte point on secp256k1 that decompresses correctly. SELECT then returns
   the same 33 bytes.
3. GENERATE again while GENERATED → a new key. Re-SELECT shows it, and a certificate for the old key
   is refused (`6A80`).
4. STORE DATA with a matching certificate → `9000`; SELECT returns the 98 bytes.
5. STORE DATA with a mismatched public key, Lc 97/99, or the old 130-byte form → `6A80`.
6. CERTIFIED: GENERATE → `6985`, STORE DATA → `6985`.
7. SC V2 opens. The transcript signature verifies under the certificate's key, and the certificate
   recovers to the CA. This is the client's check.
8. FACTORY RESET (PIN verified) leaves the certificate and identity unchanged. The channel still
   opens with the same key.
9. A certificate whose `s` is high is still accepted by the applet (it does not verify), and the
   helper's normalised certificate verifies under low-S rules.

### Helper changes

`TestIdentity.certStoreData(ca)` becomes `TestIdentity.provision(channel, ca)`:
- SELECT the Ident applet. If it returns 98 bytes, stop (already certified; keeps the write-once
  idempotence on a card).
- If it returns 33 bytes, use that key. Otherwise send GENERATE.
- Sign `SHA-256(pub)` with the CA, normalise to low-S, compute `v`, and send the 98-byte STORE DATA.

The SDK `createCertificate` needs the identity private key, so the helper signs with Bouncy Castle
directly (about 20 lines). The SDK's `IdentCommandSet.storeData(byte[])` still sends the payload.

Call sites to switch:
- `KeycardTest:208`
- `NoteStoreTest:158` and `:673`
- `StellarM4Test:103`
- `SimServer:137`

The comment about the 1-in-100 short key goes away, since no private key is serialised any more.

### On metal (J3R200, after reinstall)

- Install, then provision through the new helper. Log the GENERATE timing.
- `KeycardTest` (28/28), `StellarM4Test`, `NoteStoreTest` on the card.
- By hand:
  - GENERATE and STORE after certification → `6985`.
  - Identity unchanged across FACTORY RESET.
  - Probe INS `03` free memory.
- One deliberate tear: pull the card during GENERATE, then confirm SELECT shows EMPTY or GENERATED
  and recovery works.

## 6. Migration

- **Dev cards:** both J3R200s must be reinstalled to pick up the new Ident applet.
  - A reinstall gives each card a new identity, which is expected.
  - It **wipes the Keycard state, including any seed loaded on it.** Any wallet that depends on a dev
    card must be re-created or restored afterwards.
  - The note store package survives, but its notes would belong to the old seed.
- **Dev CA:** unchanged. The fixed test CA key in the test sources still signs. Only the input
  changes: it now signs a public key read from the card. Clients pinned to the dev CA need no
  change.
- **Clients:**
  - No parser change; the certificate is still 98 bytes and SELECT is unchanged.
  - Accept a set of pinned CA keys (verify against each), for active plus sealed spare.
    This is independent of this change but should land with it.
  - No signature-form change is needed in the client checked here: it normalises `s` itself and
    verifies against its pinned keys.
- **Personalization tool:** new host flow for production:
  1. SELECT Ident.
  2. GENERATE (or resume from SELECT).
  3. Read CPLC.
  4. HSM sign.
  5. Normalise.
  6. STORE DATA.
  7. Verify like the client.
  8. Append to the ceremony log.
  9. Only then rotate the ISD keys.
- **Upstream:** this diverges from upstream Keycard's personalization (their factory host generates
  identity keys the same way). Upstream's tooling can't personalise our cards, and ours can't
  personalise theirs. Reporting the upstream design is a separate owner decision.

**Rough size, a guess:** applet about 60 lines; helper and `IdentityTest` about a day; on-metal
about half a day.

## 7. Owner decisions (2026-11-12)

1. **Pre-certification gating:** none. Anyone can GENERATE until the card is certified.
2. **Certificate content:** keep `SHA-256(pubkey)` and 98 bytes. No domain separation, no serial.
3. **Resume:** SELECT exposes the GENERATED public key.
4. **Ceremony controls:** one operator, the owner, for now:
   - The HSM and its PIN are never stored with the personalization laptop.
   - The laptop is offline.
   - The owner keeps the ceremony log in the private repo or offline, never here.
   - Signatures are reconciled against cards per batch.
   - Revisit when there is a second person.
5. **Dev cards:** both are reinstalled when this lands.
6. **Upstream:** not reported.
7. **Proof of possession at GENERATE:** not added.
8. **Identity across erase:** surviving FACTORY RESET is accepted. A card keeps one identity across
   owners.

The applet work does not need the HSM. The applet never talks to it, and the tests sign with the
software dev CA. The HSM is needed only for the production personalization tool.
