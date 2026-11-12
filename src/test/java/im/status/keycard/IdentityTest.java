package im.status.keycard;

import com.licel.jcardsim.smartcardio.CardSimulator;
import com.licel.jcardsim.smartcardio.CardTerminalSimulator;
import com.licel.jcardsim.utils.AIDUtil;
import im.status.keycard.applet.IdentCommandSet;
import im.status.keycard.applet.Identifiers;
import im.status.keycard.desktop.PCSCCardChannel;
import im.status.keycard.io.APDUCommand;
import im.status.keycard.io.APDUResponse;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.spec.ECPrivateKeySpec;
import org.bouncycastle.jce.spec.ECPublicKeySpec;
import org.bouncycastle.math.ec.ECPoint;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.Security;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/**
 * The on-card identity (docs/ON_CARD_IDENTITY.md): the card generates its identity key, only the public key leaves
 * it, and the CA certificate written back must name that key. Needs a fresh card for every test, so it runs in the
 * simulator only; the card target covers it through provisioning in the other suites.
 */
public class IdentityTest {
  static final boolean SIMULATOR = "simulator".equals(System.getProperty("im.status.keycard.test.target", "card"));

  static final String CA_PRIV_HEX = "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2";
  static final String OTHER_CA_PRIV_HEX = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";

  static final int SW_OK = 0x9000;
  static final int SW_CONDITIONS = 0x6985;
  static final int SW_WRONG_DATA = 0x6A80;

  static KeyPair ca;
  static KeyPair otherCa;

  CardSimulator simulator;
  PCSCCardChannel channel;
  IdentCommandSet ident;

  @BeforeAll
  static void setupAll() throws Exception {
    if (Security.getProvider("BC") == null) {
      Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
    }
    ca = caKeyPair(CA_PRIV_HEX);
    otherCa = caKeyPair(OTHER_CA_PRIV_HEX);
  }

  @BeforeEach
  void setup() throws Exception {
    assumeTrue(SIMULATOR);
    simulator = new CardSimulator();
    install(Identifiers.KEYCARD_AID, KeycardApplet.class, Identifiers.getKeycardInstanceAID(), null);
    install(Identifiers.IDENT_AID, IdentApplet.class, Identifiers.IDENT_INSTANCE_AID, new byte[] {0x01, 0x00, 0x02, (byte) 0xC9, 0x00});
    channel = new PCSCCardChannel(CardTerminalSimulator.terminal(simulator).connect("*").getBasicChannel());
    ident = new IdentCommandSet(channel);
  }

  @Test
  @DisplayName("a new card has no identity: SELECT returns nothing, STORE DATA is refused, Keycard refuses everything")
  void emptyCard() throws Exception {
    assertEquals(0, ident.select().checkOK().getData().length);
    assertEquals(SW_CONDITIONS, ident.storeData(new byte[SharedMemory.CERT_LEN]).getSw());
    assertEquals(SW_CONDITIONS, keycardSelect().getSw());
  }

  @Test
  @DisplayName("GENERATE IDENTITY returns a compressed secp256k1 point, and SELECT then returns the same key")
  void generate() throws Exception {
    ident.select().checkOK();
    byte[] pub = TestIdentity.generate(channel);

    assertEquals(IdentApplet.ID_PUB_LEN, pub.length);
    assertTrue(pub[0] == 0x02 || pub[0] == 0x03);
    ECPoint p = TestIdentity.CURVE.getCurve().decodePoint(pub);
    assertTrue(p.isValid());

    assertArrayEquals(pub, ident.select().checkOK().getData());
    assertEquals(SW_CONDITIONS, keycardSelect().getSw()); // generated is not certified
  }

  @Test
  @DisplayName("generating again replaces the key, and a certificate for the old key is refused")
  void regenerate() throws Exception {
    ident.select().checkOK();
    byte[] first = TestIdentity.generate(channel);
    byte[] second = TestIdentity.generate(channel);
    assertFalse(Arrays.equals(first, second));
    assertArrayEquals(second, ident.select().checkOK().getData());

    assertEquals(SW_WRONG_DATA, ident.storeData(TestIdentity.certify(ca, first)).getSw());
    assertEquals(SW_OK, ident.storeData(TestIdentity.certify(ca, second)).getSw());
  }

  @Test
  @DisplayName("STORE DATA of a matching certificate certifies the card; SELECT returns it and it recovers to the CA")
  void certify() throws Exception {
    byte[] cert = TestIdentity.provision(channel, ca);

    assertArrayEquals(cert, ident.select().checkOK().getData());
    assertEquals(SW_OK, keycardSelect().getSw());

    byte[] hash = java.security.MessageDigest.getInstance("SHA-256").digest(Arrays.copyOf(cert, 33));
    BigInteger r = new BigInteger(1, Arrays.copyOfRange(cert, 33, 65));
    BigInteger s = new BigInteger(1, Arrays.copyOfRange(cert, 65, 97));
    assertTrue(s.compareTo(TestIdentity.CURVE.getN().shiftRight(1)) <= 0, "low S");
    byte[] caPub = ((org.bouncycastle.jce.interfaces.ECPublicKey) ca.getPublic()).getQ().getEncoded(true);
    assertArrayEquals(caPub, TestIdentity.recover(cert[97], hash, r, s).getEncoded(true));
  }

  @Test
  @DisplayName("STORE DATA refuses wrong lengths, the old certificate-plus-private-key form and another key")
  void storeRejects() throws Exception {
    ident.select().checkOK();
    byte[] pub = TestIdentity.generate(channel);
    byte[] cert = TestIdentity.certify(ca, pub);

    assertEquals(SW_WRONG_DATA, ident.storeData(Arrays.copyOf(cert, 97)).getSw());
    assertEquals(SW_WRONG_DATA, ident.storeData(Arrays.copyOf(cert, 99)).getSw());
    assertEquals(SW_WRONG_DATA, ident.storeData(Arrays.copyOf(cert, SharedMemory.CERT_LEN + 32)).getSw());

    byte[] otherPub = TestIdentity.CURVE.getG().multiply(BigInteger.valueOf(12345)).getEncoded(true);
    assertEquals(SW_WRONG_DATA, ident.storeData(TestIdentity.certify(ca, otherPub)).getSw());

    // none of the refusals moved the state: the right certificate still goes in
    assertArrayEquals(pub, ident.select().checkOK().getData());
    assertEquals(SW_OK, ident.storeData(cert).getSw());
  }

  @Test
  @DisplayName("a certified identity is frozen: GENERATE and STORE DATA are refused and the certificate stays")
  void frozen() throws Exception {
    byte[] cert = TestIdentity.provision(channel, ca);

    ident.select().checkOK();
    APDUResponse gen = channel.send(new APDUCommand(0x80, TestIdentity.GENERATE_IDENTITY, 0, 0, new byte[0], true));
    assertEquals(SW_CONDITIONS, gen.getSw());
    assertEquals(SW_CONDITIONS, ident.storeData(cert).getSw());
    assertEquals(SW_CONDITIONS, ident.storeData(TestIdentity.certify(otherCa, Arrays.copyOf(cert, 33))).getSw());

    assertArrayEquals(cert, ident.select().checkOK().getData());
  }

  @Test
  @DisplayName("the secure channel opens under the certified key, and only for a client pinning the issuing CA")
  void secureChannel() throws Exception {
    TestIdentity.provision(channel, ca);

    TestKeycardCommandSet good = new TestKeycardCommandSet(channel, caPub(ca));
    good.select().checkOK();
    good.autoOpenSecureChannel();
    assertEquals(SW_OK, good.getStatus(KeycardApplet.GET_STATUS_P1_APPLICATION).getSw());

    // the SDK checks the certificate against the pinned CA as soon as SELECT returns it
    TestKeycardCommandSet wrongCa = new TestKeycardCommandSet(channel, caPub(otherCa));
    assertThrows(java.io.IOException.class, wrongCa::select);
  }

  @Test
  @DisplayName("FACTORY RESET leaves the identity: same certificate, and the channel still opens under it")
  void survivesFactoryReset() throws Exception {
    byte[] cert = TestIdentity.provision(channel, ca);

    TestKeycardCommandSet cmdSet = new TestKeycardCommandSet(channel, caPub(ca));
    cmdSet.select().checkOK();
    assertEquals(SW_OK, cmdSet.factoryReset().getSw()); // uninitialized, so no PIN is needed

    assertArrayEquals(cert, ident.select().checkOK().getData());
    cmdSet.select().checkOK();
    cmdSet.autoOpenSecureChannel();
  }

  APDUResponse keycardSelect() throws Exception {
    return channel.send(new APDUCommand(0x00, 0xA4, 0x04, 0x00, Identifiers.getKeycardInstanceAID(), true));
  }

  static byte[] caPub(KeyPair kp) {
    return ((org.bouncycastle.jce.interfaces.ECPublicKey) kp.getPublic()).getQ().getEncoded(true);
  }

  void install(byte[] aid, Class<? extends javacard.framework.Applet> applet, byte[] instanceAid, byte[] params) throws Exception {
    ByteArrayOutputStream bos = new ByteArrayOutputStream();
    bos.write(instanceAid.length);
    bos.write(instanceAid);
    if (params != null) {
      bos.write(params);
    }
    simulator.installApplet(AIDUtil.create(aid), applet, bos.toByteArray(), (short) 0, (byte) bos.size());
  }

  static KeyPair caKeyPair(String privHex) throws Exception {
    ECParameterSpec spec = ECNamedCurveTable.getParameterSpec("secp256k1");
    KeyFactory kf = KeyFactory.getInstance("ECDSA", "BC");
    BigInteger d = new BigInteger(privHex, 16);
    org.bouncycastle.math.ec.ECPoint q = spec.getG().multiply(d).normalize();
    return new KeyPair(kf.generatePublic(new ECPublicKeySpec(q, spec)), kf.generatePrivate(new ECPrivateKeySpec(d, spec)));
  }
}
