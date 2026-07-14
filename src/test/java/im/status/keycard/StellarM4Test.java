package im.status.keycard;

import com.licel.jcardsim.smartcardio.CardSimulator;
import com.licel.jcardsim.smartcardio.CardTerminalSimulator;
import com.licel.jcardsim.utils.AIDUtil;
import im.status.keycard.applet.Certificate;
import im.status.keycard.applet.Identifiers;
import im.status.keycard.applet.IdentCommandSet;
import im.status.keycard.applet.KeycardCommandSet;
import im.status.keycard.desktop.PCSCCardChannel;
import im.status.keycard.io.APDUResponse;
import org.bitcoinj.crypto.MnemonicCode;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.spec.ECPrivateKeySpec;
import org.bouncycastle.jce.spec.ECPublicKeySpec;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.stellar.sdk.Account;
import org.stellar.sdk.KeyPair;
import org.stellar.sdk.ManageDataOperation;
import org.stellar.sdk.Network;
import org.stellar.sdk.Transaction;
import org.stellar.sdk.TransactionBuilder;
import org.stellar.sdk.xdr.DecoratedSignature;
import org.stellar.sdk.xdr.Signature;
import org.stellar.sdk.xdr.SignatureHint;

import javax.smartcardio.Card;
import javax.smartcardio.CardChannel;
import javax.smartcardio.CardTerminal;
import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * M4: end-to-end proof that the card signs a real Stellar transaction.
 *
 * The card's responsibility (per docs/ED25519.md) is to derive the SLIP-0010 Stellar key and sign
 * the 32-byte transaction hash; the host builds the XDR and assembles the DecoratedSignature. This
 * test drives that flow against the applet in jcardsim and validates the result with the official
 * Stellar Java SDK: it builds a real testnet transaction from the SEP-0005 account, has the card
 * sign the transaction hash, attaches the signature as a DecoratedSignature, and verifies it exactly
 * as Stellar would.
 */
public class StellarM4Test {
  // SEP-0005 test vector 1
  private static final String MNEMONIC =
      "illness spike retreat truth genius clock brain pass fit cave bargain toe";
  private static final String EXPECTED_G =
      "GDRXE2BQUC3AZNPVFSCEZ76NJ3WWL25FYFK6RGZGIEKWE4SOOHSUJUJ6";
  private static final String STELLAR_PATH = "m/44'/148'/0'";

  private static final String CA_PRIV_HEX =
      "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2";

  private static CardSimulator simulator;
  private static KeycardCommandSet cmdSet;

  @BeforeAll
  static void setup() throws Exception {
    if (java.security.Security.getProvider("BC") == null) {
      java.security.Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
    }

    simulator = new CardSimulator();

    java.security.KeyPair caKeyPair = buildCaKeyPair();

    installApplet(Identifiers.KEYCARD_AID, KeycardApplet.class, Identifiers.getKeycardInstanceAID(), null);
    installApplet(Identifiers.CASH_AID, CashApplet.class, Identifiers.CASH_INSTANCE_AID, new byte[] {0x01, 0x00, 0x02, (byte) 0xC9, 0x00});
    installApplet(Identifiers.IDENT_AID, IdentApplet.class, Identifiers.IDENT_INSTANCE_AID, new byte[] {0x01, 0x00, 0x02, (byte) 0xC9, 0x00});

    CardTerminal terminal = CardTerminalSimulator.terminal(simulator);
    Card card = terminal.connect("*");
    CardChannel channel = card.getBasicChannel();
    PCSCCardChannel sdkChannel = new PCSCCardChannel(channel);

    im.status.keycard.applet.Certificate cert = Certificate.createCertificate(caKeyPair, Certificate.generateIdentKeyPair());
    IdentCommandSet idCmdSet = new IdentCommandSet(sdkChannel);
    idCmdSet.select().checkOK();
    idCmdSet.storeData(cert.toStoreData()).checkOK();

    byte[] caCompressed = ((org.bouncycastle.jce.interfaces.ECPublicKey) caKeyPair.getPublic()).getQ().getEncoded(true);
    cmdSet = new KeycardCommandSet(sdkChannel, caCompressed);
    cmdSet.select().checkOK();

    // A fresh jcardsim-installed applet is uninitialized; INIT sets PIN/PUK/pairing.
    if (!cmdSet.getApplicationInfo().isInitializedCard()) {
      cmdSet.init("000000", "024680", "012345678901", new byte[0], (byte) 3, (byte) 5).checkOK();
      cmdSet.select().checkOK();
    }

    cmdSet.autoOpenSecureChannel();
    assertEquals(0x9000, cmdSet.verifyPIN("000000").getSw());

    // Load the SEP-0005 seed so the card holds the SLIP-0010 ed25519 master.
    byte[] seed = MnemonicCode.toSeed(Arrays.asList(MNEMONIC.split(" ")), "");
    assertEquals(0x9000, cmdSet.loadKey(seed).getSw());
  }

  @Test
  @DisplayName("card signs a real Stellar testnet transaction")
  void signsStellarTransaction() throws Exception {
    // 1. Export the Stellar public key and confirm the G-address matches SEP-0005.
    byte[] path = {
        (byte) 0x80, 0x00, 0x00, 0x2C,
        (byte) 0x80, 0x00, 0x00, (byte) 0x94,
        (byte) 0x80, 0x00, 0x00, 0x00
    };
    APDUResponse resp = cmdSet.exportKey(KeycardApplet.DERIVE_P1_SOURCE_MASTER, KeycardApplet.EXPORT_KEY_P2_ED25519_PUBLIC, path);
    byte[] tmpl = resp.getData();
    System.out.println("[m4] export SW=" + Integer.toHexString(resp.getSw()) + " resp (" + tmpl.length + " bytes): " + hex(tmpl));
    assertEquals(0x9000, resp.getSw());
    byte[] pubKey = Arrays.copyOfRange(tmpl, 4, 4 + tmpl[3]);
    assertEquals(32, pubKey.length);

    KeyPair account = KeyPair.fromPublicKey(pubKey);
    assertEquals(EXPECTED_G, account.getAccountId(), "card pubkey must strkey to the SEP-0005 G-address");

    // 2. Build a real Stellar testnet transaction from that account.
    Account source = new Account(account.getAccountId(), 103720918407774219L);
    Transaction tx = new TransactionBuilder(source, Network.TESTNET)
        .addOperation(new ManageDataOperation.Builder("kenter", "on-card-signed".getBytes()).build())
        .addMemo(org.stellar.sdk.Memo.text("kenter-m4"))
        .setBaseFee(100)
        .setTimeout(300)
        .build();

    byte[] txHash = tx.hash(); // 32-byte SHA-256 of the signature base — exactly what the card signs.
    assertEquals(32, txHash.length);

    // 3. Sign the transaction hash on-card via SIGN (P2 = Ed25519), SLIP-0010 path.
    resp = cmdSet.signWithPath(txHash, STELLAR_PATH, KeycardCommandSet.SIGN_P2_EDDSA_ED25519, false);
    assertEquals(0x9000, resp.getSw());
    byte[] sigResp = resp.getData();

    byte[] sigPub = extractPub(sigResp);
    assertArrayEquals(pubKey, sigPub, "SIGN pubkey must equal the exported Stellar pubkey");
    byte[] sig = extractSig(sigResp);
    assertEquals(64, sig.length);

    // 4. Verify the signature the way Stellar does, and attach it as a DecoratedSignature.
    assertTrue(account.verify(txHash, sig), "card signature must verify against the Stellar account");

    SignatureHint hint = new SignatureHint();
    hint.setSignatureHint(Arrays.copyOfRange(pubKey, pubKey.length - 4, pubKey.length));
    Signature xdrSig = new Signature();
    xdrSig.setSignature(sig);
    DecoratedSignature decorated = new DecoratedSignature();
    decorated.setHint(hint);
    decorated.setSignature(xdrSig);
    tx.addSignature(decorated);

    // The signed envelope must round-trip through XDR and still carry a hint that matches the key.
    String envelopeXdr = tx.toEnvelopeXdrBase64();
    assertTrue(envelopeXdr.length() > 0);
    assertArrayEquals(
        Arrays.copyOfRange(pubKey, pubKey.length - 4, pubKey.length),
        tx.getSignatures().get(0).getHint().getSignatureHint(),
        "DecoratedSignature hint must be the last 4 bytes of the public key");

    System.out.println("[m4] account:  " + account.getAccountId());
    System.out.println("[m4] tx hash:  " + hex(txHash));
    System.out.println("[m4] card sig: " + hex(sig));
    System.out.println("[m4] signed envelope (XDR base64):");
    System.out.println(envelopeXdr);
  }

  private static byte[] extractPub(byte[] sig) {
    // A0 81 <len> 80 20 <pub..> ...
    int pubLen = sig[4];
    return Arrays.copyOfRange(sig, 5, 5 + pubLen);
  }

  private static byte[] extractSig(byte[] sig) {
    int off = sig[4] + 5; // after the pubkey TLV value
    // 88 40 <sig>
    return Arrays.copyOfRange(sig, off + 2, off + 2 + sig[off + 1]);
  }

  private static void installApplet(byte[] aid, Class<? extends javacard.framework.Applet> applet, byte[] instanceAid, byte[] params) throws Exception {
    ByteArrayOutputStream bos = new ByteArrayOutputStream();
    bos.write(instanceAid.length);
    bos.write(instanceAid);
    if (params != null) {
      bos.write(params);
    }
    simulator.installApplet(AIDUtil.create(aid), applet, bos.toByteArray(), (short) 0, (byte) bos.size());
  }

  private static java.security.KeyPair buildCaKeyPair() throws Exception {
    ECParameterSpec caSpec = ECNamedCurveTable.getParameterSpec("secp256k1");
    KeyFactory kf = KeyFactory.getInstance("EC", "BC");
    BigInteger caPriv = new BigInteger(CA_PRIV_HEX, 16);
    ECPrivateKeySpec caPrivSpec = new ECPrivateKeySpec(caPriv, caSpec);
    ECPublicKeySpec caPubSpec = new ECPublicKeySpec(caSpec.getG().multiply(caPriv), caSpec);
    return new java.security.KeyPair(kf.generatePublic(caPubSpec), kf.generatePrivate(caPrivSpec));
  }

  private static String hex(byte[] b) {
    StringBuilder sb = new StringBuilder();
    for (byte x : b) {
      sb.append(String.format("%02x", x));
    }
    return sb.toString();
  }
}
