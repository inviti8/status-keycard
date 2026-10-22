package im.status.keycard;

import com.licel.jcardsim.smartcardio.CardSimulator;
import com.licel.jcardsim.smartcardio.CardTerminalSimulator;
import com.licel.jcardsim.utils.AIDUtil;
import im.status.keycard.applet.*;
import im.status.keycard.applet.Certificate;
import im.status.keycard.desktop.PCSCCardChannel;
import static im.status.keycard.SecureChannelV2.PUBKEY_SIZE;
import im.status.keycard.io.APDUCommand;
import im.status.keycard.io.APDUResponse;
import javacard.framework.AID;
import org.bitcoinj.core.ECKey;
import org.apache.commons.codec.binary.Base32;
import org.bitcoinj.crypto.ChildNumber;
import org.bitcoinj.crypto.DeterministicKey;
import org.bitcoinj.crypto.HDKeyDerivation;
import org.bitcoinj.crypto.MnemonicCode;
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;
import org.bouncycastle.crypto.signers.Ed25519Signer;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.spec.ECPublicKeySpec;
import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.*;
import org.web3j.crypto.*;
import org.web3j.protocol.Web3j;
import org.web3j.protocol.core.DefaultBlockParameterName;
import org.web3j.protocol.core.methods.request.RawTransaction;
import org.web3j.protocol.core.methods.response.EthSendTransaction;
import org.web3j.protocol.http.HttpService;
import org.web3j.tx.Transfer;
import org.web3j.utils.Convert;
import org.web3j.utils.Numeric;

import javax.smartcardio.*;
import java.io.ByteArrayOutputStream;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.math.BigDecimal;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.*;

import org.bouncycastle.jce.interfaces.ECPublicKey;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Random;

import static org.apache.commons.codec.digest.DigestUtils.sha256;
import static org.junit.jupiter.api.Assertions.*;

import apdu4j.pcsc.TerminalManager;

@DisplayName("Test the Keycard Applet")
public class KeycardTest {
  private static CardTerminal cardTerminal;
  private static CardChannel apduChannel;
  private static im.status.keycard.io.CardChannel sdkChannel;
  private static CardSimulator simulator;
  private static KeyPair caKeyPair;

  private TestKeycardCommandSet cmdSet;

  private static final int TARGET_SIMULATOR = 0;
  private static final int TARGET_CARD = 1;

  private static final int TARGET;

  static {
    switch(System.getProperty("im.status.keycard.test.target", "card")) {
      case "simulator":
        TARGET = TARGET_SIMULATOR;
        break;
      case "card":
        TARGET = TARGET_CARD;
        break;
      default:
        throw new RuntimeException("Unknown target");
    }
  }

  @BeforeAll
  static void initAll() throws Exception {
    switch(TARGET) {
      case TARGET_SIMULATOR:
        openSimulatorChannel();
        break;
      case TARGET_CARD:
        openCardChannel();
        break;
      default:
        throw new IllegalStateException("Unknown target");
    }

    // Fixed CA keypair for reproducible tests
    ECParameterSpec caSpec = ECNamedCurveTable.getParameterSpec("secp256k1");
    java.security.KeyFactory kf = java.security.KeyFactory.getInstance("EC", "BC");
    java.math.BigInteger caPriv = new java.math.BigInteger("a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2", 16);
    org.bouncycastle.jce.spec.ECPrivateKeySpec caPrivSpec = new org.bouncycastle.jce.spec.ECPrivateKeySpec(caPriv, caSpec);
    org.bouncycastle.jce.spec.ECPublicKeySpec caPubSpec = new org.bouncycastle.jce.spec.ECPublicKeySpec(caSpec.getG().multiply(caPriv), caSpec);
    caKeyPair = new java.security.KeyPair(kf.generatePublic(caPubSpec), kf.generatePrivate(caPrivSpec));

    initIfNeeded();
  }

  private static void initCapabilities(ApplicationInfo info) {
    HashSet<String> capabilities = new HashSet<>();

    if (info.hasSecureChannelCapability()) {
      capabilities.add("secureChannel");
    }

    if (info.hasCredentialsManagementCapability()) {
      capabilities.add("credentialsManagement");
    }

    if (info.hasKeyManagementCapability()) {
      capabilities.add("keyManagement");
    }

    if (info.hasNDEFCapability()) {
      capabilities.add("ndef");
    }

    if (info.hasFactoryResetCapability()) {
      capabilities.add("factoryReset");
    }

    CapabilityCondition.availableCapabilities = capabilities;
  }

  private static void openSimulatorChannel() throws Exception {
    simulator = new CardSimulator();

    // Install KeycardApplet
    AID aid = AIDUtil.create(Identifiers.KEYCARD_AID);
    ByteArrayOutputStream bos = new ByteArrayOutputStream();
    bos.write(Identifiers.getKeycardInstanceAID().length);
    bos.write(Identifiers.getKeycardInstanceAID());

    simulator.installApplet(aid, KeycardApplet.class, bos.toByteArray(), (short) 0, (byte) bos.size());
    bos.reset();

    // Install NDEFApplet
    aid = AIDUtil.create(Identifiers.NDEF_AID);
    bos.write(Identifiers.NDEF_INSTANCE_AID.length);
    bos.write(Identifiers.NDEF_INSTANCE_AID);
    bos.write(new byte[] {0x01, 0x00, 0x02, (byte) 0xC9, 0x00});

    simulator.installApplet(aid, NDEFApplet.class, bos.toByteArray(), (short) 0, (byte) bos.size());
    bos.reset();

    // Install CashApplet
    aid = AIDUtil.create(Identifiers.CASH_AID);
    bos.write(Identifiers.CASH_INSTANCE_AID.length);
    bos.write(Identifiers.CASH_INSTANCE_AID);
    bos.write(new byte[] {0x01, 0x00, 0x02, (byte) 0xC9, 0x00});

    simulator.installApplet(aid, CashApplet.class, bos.toByteArray(), (short) 0, (byte) bos.size());
    bos.reset();

    // Install CashApplet
    aid = AIDUtil.create(Identifiers.IDENT_AID);
    bos.write(Identifiers.IDENT_INSTANCE_AID.length);
    bos.write(Identifiers.IDENT_INSTANCE_AID);
    bos.write(new byte[] {0x01, 0x00, 0x02, (byte) 0xC9, 0x00});

    simulator.installApplet(aid, IdentApplet.class, bos.toByteArray(), (short) 0, (byte) bos.size());
    bos.reset();    

    cardTerminal = CardTerminalSimulator.terminal(simulator);

    openPCSCChannel();
  }

  private static void openCardChannel() throws Exception {
    TerminalFactory tf = TerminalManager.getTerminalFactory();

    for (CardTerminal t : tf.terminals().list()) {
      if (t.isCardPresent()) {
        cardTerminal = t;
        break;
      }
    }

    openPCSCChannel();
  }

  private static void openPCSCChannel() throws Exception {
    Card apduCard = cardTerminal.connect("*");
    apduChannel = apduCard.getBasicChannel();
    sdkChannel = new PCSCCardChannel(apduChannel);
  }

  private static void initCard(KeycardCommandSet cmdSet) throws Exception {
    assertEquals(0x9000, cmdSet.init("000000", "024680", "012345678901", new byte[0], (byte) 3, (byte) 5).getSw());
    cmdSet.select().checkOK();
  }

  private static void initIfNeeded() throws Exception {
    IdentCommandSet idCmdSet = new IdentCommandSet(sdkChannel);
    idCmdSet.select().checkOK();
    // write-once: a card from an earlier run already holds a certificate from the same test CA
    idCmdSet.storeData(TestIdentity.certStoreData(caKeyPair)).checkSW(0x9000, 0x6985);

    KeycardCommandSet cmdSet = new KeycardCommandSet(sdkChannel,((org.bouncycastle.jce.interfaces.ECPublicKey) caKeyPair.getPublic()).getQ().getEncoded(true));
    cmdSet.select().checkOK();

    initCapabilities(cmdSet.getApplicationInfo());

    if (!cmdSet.getApplicationInfo().isInitializedCard()) {
      initCard(cmdSet);
      initCapabilities(cmdSet.getApplicationInfo());
    }
  }

  @BeforeEach
  void init() throws Exception {
    reset();
    cmdSet = new TestKeycardCommandSet(sdkChannel, ((org.bouncycastle.jce.interfaces.ECPublicKey) caKeyPair.getPublic()).getQ().getEncoded(true));
    cmdSet.select().checkOK();
  }

  @AfterEach
  void tearDown() throws Exception {
    resetAndSelectAndOpenSC();

    if (cmdSet.getApplicationInfo().hasCredentialsManagementCapability()) {
      APDUResponse response = cmdSet.verifyPIN("000000");
      assertEquals(0x9000, response.getSw());
    }
  }

  @Test
  @DisplayName("SELECT command")
  void selectTest() throws Exception {
    APDUResponse response = cmdSet.select();
    assertEquals(0x9000, response.getSw());
    byte[] data = response.getData();
    assertTrue(new ApplicationInfo(data).isInitializedCard());

    // The Application Info Template (0xA4) length must exactly match its content so a strict
    // BER-TLV parser does not truncate the trailing identity certificate (tag 0x8A), which the
    // V2 secure channel needs. Regression guard for the off-by-one in selectApplet().
    assertEquals(KeycardApplet.TLV_APPLICATION_INFO_TEMPLATE, data[0]);
    int declaredLen;
    int contentStart;
    if ((data[1] & 0xFF) == 0x81) {          // BER long-form (initialized card)
      declaredLen = data[2] & 0xFF;
      contentStart = 3;
    } else {                                  // short-form (uninitialized card)
      declaredLen = data[1] & 0xFF;
      contentStart = 2;
    }
    assertEquals(data.length - contentStart, declaredLen, "A4 template length must equal its content length");
  }

  @Test
  @DisplayName("OPEN SECURE CHANNEL command")
  @Capabilities("secureChannel")
  void openSecureChannelTest() throws Exception {
    APDUResponse response;

    // ----- Bad/edge case: wrong data length -----
    // Too short (only salt, no public key)
    byte[] salt = new byte[32];
    response = sdkChannel.send(new APDUCommand(0x80, (byte) 0x10, 0x00, 0x00, salt));
    assertEquals(0x6A80, response.getSw());

    // Too long (salt + public key + extra byte)
    byte[] clientPubKey = new byte[65];
    clientPubKey[0] = 0x04;
    for (int i = 1; i < clientPubKey.length; i++) {
      clientPubKey[i] = (byte) i;
    }
    byte[] tooLongData = new byte[98];
    System.arraycopy(salt, 0, tooLongData, 0, 32);
    System.arraycopy(clientPubKey, 0, tooLongData, 32, 65);
    tooLongData[97] = (byte) 0xAA;
    response = sdkChannel.send(new APDUCommand(0x80, (byte) 0x10, 0x00, 0x00, tooLongData));
    assertEquals(0x6A80, response.getSw());

    // Empty data
    response = sdkChannel.send(new APDUCommand(0x80, (byte) 0x10, 0x00, 0x00, new byte[0]));
    assertEquals(0x6A80, response.getSw());

    // ----- Bad/edge case: public key does not start with 0x04 (uncompressed indicator) -----
    byte[] badPubKey = new byte[65];
    badPubKey[0] = 0x03; // compressed-style prefix instead of 0x04
    byte[] dataWithBadPubKey = new byte[97];
    for (int i = 0; i < 32; i++) dataWithBadPubKey[i] = (byte) i;
    System.arraycopy(badPubKey, 0, dataWithBadPubKey, 32, 65);
    response = sdkChannel.send(new APDUCommand(0x80, (byte) 0x10, 0x00, 0x00, dataWithBadPubKey));
    assertEquals(0x6A80, response.getSw());

    // ----- Bad/edge case: public key is 65 bytes but starts with 0x00 (invalid) -----
    byte[] zeroPrefixPubKey = new byte[65];
    zeroPrefixPubKey[0] = 0x00;
    byte[] dataWithZeroPrefix = new byte[97];
    for (int i = 0; i < 32; i++) dataWithZeroPrefix[i] = (byte) i;
    System.arraycopy(zeroPrefixPubKey, 0, dataWithZeroPrefix, 32, 65);
    response = sdkChannel.send(new APDUCommand(0x80, (byte) 0x10, 0x00, 0x00, dataWithZeroPrefix));
    assertEquals(0x6A80, response.getSw());

    // ----- Bad/edge case: public key is 64 bytes (too short for uncompressed) -----
    byte[] shortPubKey = new byte[64];
    shortPubKey[0] = 0x04;
    for (int i = 1; i < shortPubKey.length; i++) {
      shortPubKey[i] = (byte) (i + 10);
    }
    byte[] dataWithShortPubKey = new byte[96];
    for (int i = 0; i < 32; i++) dataWithShortPubKey[i] = (byte) i;
    System.arraycopy(shortPubKey, 0, dataWithShortPubKey, 32, 64);
    response = sdkChannel.send(new APDUCommand(0x80, (byte) 0x10, 0x00, 0x00, dataWithShortPubKey));
    assertEquals(0x6A80, response.getSw());

    // ----- Bad/edge case: public key format is valid (0x04, 65 bytes) but not a valid curve point -----
    byte[] invalidCurvePubKey = new byte[65];
    invalidCurvePubKey[0] = 0x04;
    // X = 0, Y = 0 — not on secp256k1 (y² ≠ x³ + 7)
    byte[] dataWithInvalidCurveKey = new byte[97];
    for (int i = 0; i < 32; i++) dataWithInvalidCurveKey[i] = (byte) i;
    System.arraycopy(invalidCurvePubKey, 0, dataWithInvalidCurveKey, 32, 65);
    response = sdkChannel.send(new APDUCommand(0x80, (byte) 0x10, 0x00, 0x00, dataWithInvalidCurveKey));
    assertEquals(0x6A80, response.getSw());

    // ----- Bad/edge case: wrong P1 or P2 -----
    response = sdkChannel.send(new APDUCommand(0x80, (byte) 0x10, 0x01, 0x00, dataWithBadPubKey));
    assertEquals(0x6A86, response.getSw());

    response = sdkChannel.send(new APDUCommand(0x80, (byte) 0x10, 0x00, 0x01, dataWithBadPubKey));
    assertEquals(0x6A86, response.getSw());

    // ----- Good case: valid openSecureChannel -----
    // Generate a proper secp256k1 key pair for the client
    java.security.KeyPairGenerator g = java.security.KeyPairGenerator.getInstance("EC", "BC");
    org.bouncycastle.jce.spec.ECParameterSpec ecSpec =
        org.bouncycastle.jce.ECNamedCurveTable.getParameterSpec("secp256k1");
    g.initialize(ecSpec);
    java.security.KeyPair clientKeyPair = g.generateKeyPair();
    byte[] clientPublicKey = ((org.bouncycastle.jce.interfaces.ECPublicKey) clientKeyPair.getPublic())
        .getQ().getEncoded(false);

    // Build the request: 32-byte salt + 65-byte uncompressed public key
    byte[] requestData = new byte[97];
    byte[] clientSalt = new byte[32];
    for (int i = 0; i < 32; i++) {
      clientSalt[i] = (byte) (i + 1);
    }
    System.arraycopy(clientSalt, 0, requestData, 0, 32);
    System.arraycopy(clientPublicKey, 0, requestData, 32, 65);

    response = sdkChannel.send(new APDUCommand(0x80, (byte) 0x10, 0x00, 0x00, requestData));
    assertEquals(0x9000, response.getSw());

    // Response should be: 65-byte card ephemeral public key + ECDSA signature
    byte[] respData = response.getData();
    assertTrue(respData.length >= PUBKEY_SIZE + 70, "Response too short");
    assertTrue(respData.length <= PUBKEY_SIZE + 72, "Response too long");

    // Card's ephemeral public key should start with 0x04
    assertEquals(0x04, respData[0]);

    // ----- Good case: open a second secure channel (fresh key exchange) -----
    java.security.KeyPair clientKeyPair2 = g.generateKeyPair();
    byte[] clientPublicKey2 = ((org.bouncycastle.jce.interfaces.ECPublicKey) clientKeyPair2.getPublic())
        .getQ().getEncoded(false);

    byte[] requestData2 = new byte[97];
    byte[] clientSalt2 = new byte[32];
    for (int i = 0; i < 32; i++) {
      clientSalt2[i] = (byte) (i + 100);
    }
    System.arraycopy(clientSalt2, 0, requestData2, 0, 32);
    System.arraycopy(clientPublicKey2, 0, requestData2, 32, 65);

    response = sdkChannel.send(new APDUCommand(0x80, (byte) 0x10, 0x00, 0x00, requestData2));
    assertEquals(0x9000, response.getSw());
    respData = response.getData();
    assertEquals(0x04, respData[0]);
  }

  @Test
  @DisplayName("GET STATUS command")
  void getStatusTest() throws Exception {
    APDUResponse response;

    if (cmdSet.getApplicationInfo().hasSecureChannelCapability()) {
      // Security condition violation: SecureChannel not open
      response = cmdSet.getStatus(KeycardApplet.GET_STATUS_P1_APPLICATION);
      assertEquals(0x6985, response.getSw());
      cmdSet.autoOpenSecureChannel();
    }

    // Good case. Since the order of test execution is undefined, the test cannot know if the keys are initialized or not.
    // Additionally, support for public key derivation is hw dependent.
    response = cmdSet.getStatus(KeycardApplet.GET_STATUS_P1_APPLICATION);
    assertEquals(0x9000, response.getSw());
    ApplicationStatus status = new ApplicationStatus(response.getData());

    if (cmdSet.getApplicationInfo().hasCredentialsManagementCapability()) {
      assertEquals(3, status.getPINRetryCount());
      assertEquals(5, status.getPUKRetryCount());

      response = cmdSet.verifyPIN("123456");
      assertEquals(0x63C2, response.getSw());
      response = cmdSet.getStatus(KeycardApplet.GET_STATUS_P1_APPLICATION);
      assertEquals(0x9000, response.getSw());
      status = new ApplicationStatus(response.getData());
      assertEquals(2, status.getPINRetryCount());
      assertEquals(5, status.getPUKRetryCount());

      response = cmdSet.verifyPIN("000000");
      assertEquals(0x9000, response.getSw());
      response = cmdSet.getStatus(KeycardApplet.GET_STATUS_P1_APPLICATION);
      assertEquals(0x9000, response.getSw());
      status = new ApplicationStatus(response.getData());
      assertEquals(3, status.getPINRetryCount());
      assertEquals(5, status.getPUKRetryCount());
    } else {
      assertEquals((byte) 0xff, status.getPINRetryCount());
      assertEquals((byte) 0xff, status.getPUKRetryCount());
    }
  }

  @Test
  @DisplayName("VERIFY PIN command")
  @Capabilities("credentialsManagement")
  void verifyPinTest() throws Exception {
    // Security condition violation: SecureChannel not open
    APDUResponse response = cmdSet.verifyPIN("000000");
    assertEquals(0x6985, response.getSw());

    cmdSet.autoOpenSecureChannel();

    // Wrong format
    response = cmdSet.verifyPIN("12345");
    assertEquals(0x6a80, response.getSw());

    response = cmdSet.verifyPIN("12345a");
    assertEquals(0x6a80, response.getSw());

    // Wrong PIN
    response = cmdSet.verifyPIN("123456");
    assertEquals(0x63C2, response.getSw());

    // Correct PIN
    response = cmdSet.verifyPIN("000000");
    assertEquals(0x9000, response.getSw());

    // Alt PIN
    response = cmdSet.verifyPIN("024680");
    assertEquals(0x9000, response.getSw());    

    // Check max retry counter
    response = cmdSet.verifyPIN("123456");
    assertEquals(0x63C2, response.getSw());

    response = cmdSet.verifyPIN("123456");
    assertEquals(0x63C1, response.getSw());

    response = cmdSet.verifyPIN("123456");
    assertEquals(0x63C0, response.getSw());

    response = cmdSet.verifyPIN("000000");
    assertEquals(0x63C0, response.getSw());

    response = cmdSet.verifyPIN("024680");
    assertEquals(0x63C0, response.getSw());

    resetAndSelectAndOpenSC();

    if (cmdSet.getApplicationInfo().hasFactoryResetCapability()) {
      // Factory reset and re-init to start from a known, clean state. FACTORY RESET needs a verified PIN, so
      // unblock (which also verifies the new PIN) first.
      response = cmdSet.unblockPIN("012345678901", "000000");
      assertEquals(0x9000, response.getSw());
      response = cmdSet.factoryReset();
      assertEquals(0x9000, response.getSw());
      cmdSet.select().checkOK();
      initCard(cmdSet);
      cmdSet.autoOpenSecureChannel();

      // Control, below the cumulative-wrong-attempt threshold: a wrong guess
      // followed by the alt PIN leaves the main PIN usable.
      response = cmdSet.verifyPIN("111111");
      assertEquals(0x6300, response.getSw() & 0xFF00); // rejected
      response = cmdSet.verifyPIN("024680");
      assertEquals(0x9000, response.getSw());          // alt accepted
      response = cmdSet.verifyPIN("000000");
      assertEquals(0x9000, response.getSw());          // main still usable

      // Attack: alternate wrong main guesses and alt-PIN resets.
      response = cmdSet.verifyPIN("111111");
      assertEquals(0x6300, response.getSw() & 0xFF00);
      response = cmdSet.verifyPIN("024680");
      assertEquals(0x9000, response.getSw());

      response = cmdSet.verifyPIN("222222");
      assertEquals(0x6300, response.getSw() & 0xFF00);
      response = cmdSet.verifyPIN("024680");
      assertEquals(0x9000, response.getSw());

      response = cmdSet.verifyPIN("333333");
      assertEquals(0x6300, response.getSw() & 0xFF00);
      response = cmdSet.verifyPIN("024680");
      assertEquals(0x9000, response.getSw());

      response = cmdSet.verifyPIN("000000");
      assertEquals(0x6300, response.getSw() & 0xFF00);

      // Re-authenticate with the alt PIN so the PUK can be changed (the wrong
      // attempt above cleared the validated flag).
      response = cmdSet.verifyPIN("024680");
      assertEquals(0x9000, response.getSw());

      // The attacker swaps the PUK for one they know.
      response = cmdSet.changePIN(KeycardApplet.CHANGE_PIN_P1_PUK, "210987654321");
      assertEquals(0x9000, response.getSw());

      // Block the active (alt) PIN so that UNBLOCK PIN is permitted.
      response = cmdSet.verifyPIN("111111");
      assertEquals(0x6300, response.getSw() & 0xFF00);
      response = cmdSet.verifyPIN("222222");
      assertEquals(0x6300, response.getSw() & 0xFF00);
      response = cmdSet.verifyPIN("333333");
      assertEquals(0x6300, response.getSw() & 0xFF00);

      // Unblock with the attacker-known PUK. This resets the alt PIN only.
      response = cmdSet.unblockPIN("210987654321", "135790");
      assertEquals(0x9000, response.getSw());

      // UNBLOCK PIN did NOT resetAndUnblock the main PIN: the correct main
      // PIN is still rejected.
      response = cmdSet.verifyPIN("000000");
      assertEquals(0x6300, response.getSw() & 0xFF00);

      response = cmdSet.verifyPIN("135790");
      assertEquals(0x9000, response.getSw());
      response = cmdSet.verifyPIN("000000");
      assertEquals(0x6300, response.getSw() & 0xFF00);

      // Leave the card in a clean, initialized state for subsequent tests (FACTORY RESET needs a verified PIN).
      response = cmdSet.verifyPIN("135790");
      assertEquals(0x9000, response.getSw());
      response = cmdSet.factoryReset();
      assertEquals(0x9000, response.getSw());
      cmdSet.select().checkOK();
      initCard(cmdSet);
      cmdSet.autoOpenSecureChannel();
    } else {
      // Fallback (cards without the factory-reset capability): unblock the
      // main PIN so subsequent tests (and tearDown) can proceed.
      response = cmdSet.unblockPIN("012345678901", "000000");
      assertEquals(0x9000, response.getSw());
    }
  }

  @Test
  @DisplayName("CHANGE PIN command")
  @Capabilities("credentialsManagement")
  void changePinTest() throws Exception {
    // Security condition violation: SecureChannel not open
    APDUResponse response = cmdSet.changePIN(KeycardApplet.CHANGE_PIN_P1_USER_PIN, "123456");
    assertEquals(0x6985, response.getSw());

    cmdSet.autoOpenSecureChannel();

    // Security condition violation: PIN not verified
    response = cmdSet.changePIN(KeycardApplet.CHANGE_PIN_P1_USER_PIN, "123456");
    assertEquals(0x6985, response.getSw());

    response = cmdSet.verifyPIN("000000");
    assertEquals(0x9000, response.getSw());

    // Wrong P1
    response = cmdSet.changePIN(0x03, "123456");
    assertEquals(0x6a86, response.getSw());

    // Test wrong PIN formats (non-digits, too short, too long)
    response = cmdSet.changePIN(KeycardApplet.CHANGE_PIN_P1_USER_PIN, "654a21");
    assertEquals(0x6A80, response.getSw());

    response = cmdSet.changePIN(KeycardApplet.CHANGE_PIN_P1_USER_PIN, "54321");
    assertEquals(0x6A80, response.getSw());

    response = cmdSet.changePIN(KeycardApplet.CHANGE_PIN_P1_USER_PIN, "7654321");
    assertEquals(0x6A80, response.getSw());

    // Test wrong PUK formats
    response = cmdSet.changePIN(KeycardApplet.CHANGE_PIN_P1_PUK, "210987654a21");
    assertEquals(0x6A80, response.getSw());

    response = cmdSet.changePIN(KeycardApplet.CHANGE_PIN_P1_PUK, "10987654321");
    assertEquals(0x6A80, response.getSw());

    response = cmdSet.changePIN(KeycardApplet.CHANGE_PIN_P1_PUK, "3210987654321");
    assertEquals(0x6A80, response.getSw());

    // Change PIN correctly, check that after PIN change the PIN remains validated
    response = cmdSet.changePIN(KeycardApplet.CHANGE_PIN_P1_USER_PIN, "123456");
    assertEquals(0x9000, response.getSw());

    response = cmdSet.changePIN(KeycardApplet.CHANGE_PIN_P1_USER_PIN, "654321");
    assertEquals(0x9000, response.getSw());

    // Reset card and verify that the new PIN has really been set
    resetAndSelectAndOpenSC();

    response = cmdSet.verifyPIN("654321");
    assertEquals(0x9000, response.getSw());

    // Change PUK
    response = cmdSet.changePIN(KeycardApplet.CHANGE_PIN_P1_PUK, "210987654321");
    assertEquals(0x9000, response.getSw());

    resetAndSelectAndOpenSC();

    response = cmdSet.verifyPIN("000000");
    assertEquals(0x63C2, response.getSw());
    response = cmdSet.verifyPIN("000000");
    assertEquals(0x63C1, response.getSw());
    response = cmdSet.verifyPIN("000000");
    assertEquals(0x63C0, response.getSw());

    // Reset the PIN with the new PUK
    response = cmdSet.unblockPIN("210987654321", "000000");
    assertEquals(0x9000, response.getSw());

    response = cmdSet.verifyPIN("000000");
    assertEquals(0x9000, response.getSw());

    // Reset PUK
    response = cmdSet.changePIN(KeycardApplet.CHANGE_PIN_P1_PUK, "012345678901");
    assertEquals(0x9000, response.getSw());

    // Alt PIN
    response = cmdSet.verifyPIN("024680");
    assertEquals(0x9000, response.getSw());

    response = cmdSet.changePIN(KeycardApplet.CHANGE_PIN_P1_USER_PIN, "123456");
    assertEquals(0x9000, response.getSw());
    
    resetAndSelectAndOpenSC();

    response = cmdSet.verifyPIN("123456");
    assertEquals(0x9000, response.getSw());

    response = cmdSet.changePIN(KeycardApplet.CHANGE_PIN_P1_USER_PIN, "024680");
    assertEquals(0x9000, response.getSw());

    resetAndSelectAndOpenSC();

    response = cmdSet.verifyPIN("000000");
    assertEquals(0x9000, response.getSw());
  }

  @Test
  @DisplayName("UNBLOCK PIN command")
  @Capabilities("credentialsManagement")
  void unblockPinTest() throws Exception {
    // Security condition violation: SecureChannel not open
    APDUResponse response = cmdSet.unblockPIN("012345678901", "000000");
    assertEquals(0x6985, response.getSw());

    cmdSet.autoOpenSecureChannel();

    // Condition violation: PIN is not blocked
    response = cmdSet.unblockPIN("012345678901", "000000");
    assertEquals(0x6985, response.getSw());

    // Block the PIN
    response = cmdSet.verifyPIN("123456");
    assertEquals(0x63C2, response.getSw());

    response = cmdSet.verifyPIN("123456");
    assertEquals(0x63C1, response.getSw());

    response = cmdSet.verifyPIN("123456");
    assertEquals(0x63C0, response.getSw());

    // Wrong PUK formats (too short, too long)
    response = cmdSet.unblockPIN("12345678901", "000000");
    assertEquals(0x6A80, response.getSw());

    response = cmdSet.unblockPIN("1234567890123", "000000");
    assertEquals(0x6A80, response.getSw());

    // Wrong PUK
    response = cmdSet.unblockPIN("123456789010", "000000");
    assertEquals(0x63C4, response.getSw());

    // Correct PUK
    response = cmdSet.unblockPIN("012345678901", "654321");
    assertEquals(0x9000, response.getSw());

    // Check that PIN has been changed and unblocked
    resetAndSelectAndOpenSC();

    response = cmdSet.verifyPIN("654321");
    assertEquals(0x9000, response.getSw());

    // Reset the PIN to make further tests possible
    response = cmdSet.changePIN(KeycardApplet.CHANGE_PIN_P1_USER_PIN, "000000");
    assertEquals(0x9000, response.getSw());
  }

  @Test
  @DisplayName("LOAD KEY command")
  @Capabilities("keyManagement")
  void loadKeyTest() throws Exception {
    KeyPairGenerator g = keypairGenerator();
    KeyPair keyPair = g.generateKeyPair();
    APDUResponse response;

    if (cmdSet.getApplicationInfo().hasSecureChannelCapability()) {
      // Security condition violation: SecureChannel not open
      response = cmdSet.loadKey(keyPair);
      assertEquals(0x6985, response.getSw());

      cmdSet.autoOpenSecureChannel();
    }

    if (cmdSet.getApplicationInfo().hasCredentialsManagementCapability()) {
      // Security condition violation: PIN not verified
      response = cmdSet.loadKey(keyPair);
      assertEquals(0x6985, response.getSw());

      response = cmdSet.verifyPIN("000000");
      assertEquals(0x9000, response.getSw());
    }

    // Wrong key type
    response = cmdSet.loadKey(new byte[] { (byte) 0xAA, 0x02, (byte) 0x80, 0x00}, (byte) 0x00);
    assertEquals(0x6A86, response.getSw());

    // Wrong data (wrong template, missing private key, invalid keys)
    response = cmdSet.loadKey(new byte[]{(byte) 0xAA, 0x02, (byte) 0x80, 0x00}, KeycardApplet.LOAD_KEY_P1_EC);
    assertEquals(0x6A80, response.getSw());

    response = cmdSet.loadKey(new byte[]{(byte) 0xA1, 0x02, (byte) 0x80, 0x00}, KeycardApplet.LOAD_KEY_P1_EC);
    assertEquals(0x6A80, response.getSw());

    if (TARGET != TARGET_SIMULATOR) { // the simulator does not check the key format
      response = cmdSet.loadKey(new byte[]{(byte) 0xA1, 0x06, (byte) 0x80, 0x01, 0x01, (byte) 0x81, 0x01, 0x02}, KeycardApplet.LOAD_KEY_P1_EC);
      assertEquals(0x6A80, response.getSw());
    }

    byte[] chainCode = new byte[32];
    new Random().nextBytes(chainCode);

    // Correct LOAD KEY
    response = cmdSet.loadKey(keyPair);
    assertEquals(0x9000, response.getSw());
    verifyKeyUID(response.getData(), ((ECPublicKey) keyPair.getPublic()));

    keyPair = g.generateKeyPair();

    // Check extended key
    response = cmdSet.loadKey(keyPair, false, chainCode);
    assertEquals(0x9000, response.getSw());
    verifyKeyUID(response.getData(), ((ECPublicKey) keyPair.getPublic()));

    // Check omitted public key
    response = cmdSet.loadKey(keyPair, true, null);
    assertEquals(0x9000, response.getSw());
    verifyKeyUID(response.getData(), ((ECPublicKey) keyPair.getPublic()));
    response = cmdSet.loadKey(keyPair, true, chainCode);
    assertEquals(0x9000, response.getSw());
    verifyKeyUID(response.getData(), ((ECPublicKey) keyPair.getPublic()));

    byte[] seed = new byte[64];
    new Random().nextBytes(seed);

    // Check seed load
    response = cmdSet.loadKey(seed);
    assertEquals(0x9000, response.getSw());
  }

  @Test
  @DisplayName("GENERATE MNEMONIC command")
  @Capabilities("keyManagement")
  void generateMnemonicTest() throws Exception {
    // Security condition violation: SecureChannel not open
    APDUResponse response;

    if (cmdSet.getApplicationInfo().hasSecureChannelCapability()) {
      response = cmdSet.generateMnemonic(4);
      assertEquals(0x6985, response.getSw());
      cmdSet.autoOpenSecureChannel();
    }

    // Wrong P1 (too short, too long)
    response = cmdSet.generateMnemonic(3);
    assertEquals(0x6A86, response.getSw());

    response = cmdSet.generateMnemonic(9);
    assertEquals(0x6A86, response.getSw());

    // Good cases
    response = cmdSet.generateMnemonic(4);
    assertEquals(0x9000, response.getSw());
    assertMnemonic(12, response.getData());

    response = cmdSet.generateMnemonic(5);
    assertEquals(0x9000, response.getSw());
    assertMnemonic(15, response.getData());

    response = cmdSet.generateMnemonic(6);
    assertEquals(0x9000, response.getSw());
    assertMnemonic(18, response.getData());

    response = cmdSet.generateMnemonic(7);
    assertEquals(0x9000, response.getSw());
    assertMnemonic(21, response.getData());

    response = cmdSet.generateMnemonic(8);
    assertEquals(0x9000, response.getSw());
    assertMnemonic(24, response.getData());
  }

  @Test
  @DisplayName("REMOVE KEY command")
  @Capabilities("keyManagement")
  void removeKeyTest() throws Exception {
    KeyPairGenerator g = keypairGenerator();
    KeyPair keyPair = g.generateKeyPair();
    APDUResponse response;

    if (cmdSet.getApplicationInfo().hasSecureChannelCapability()) {
      // Security condition violation: SecureChannel not open
      response = cmdSet.removeKey();
      assertEquals(0x6985, response.getSw());
      cmdSet.autoOpenSecureChannel();
    }

    if (cmdSet.getApplicationInfo().hasCredentialsManagementCapability()) {
      // Security condition violation: PIN not verified
      response = cmdSet.removeKey();
      assertEquals(0x6985, response.getSw());

      response = cmdSet.verifyPIN("000000");
      assertEquals(0x9000, response.getSw());
    }

    response = cmdSet.loadKey(keyPair);
    assertEquals(0x9000, response.getSw());

    response = cmdSet.select();
    assertEquals(0x9000, response.getSw());
    ApplicationInfo info = new ApplicationInfo(response.getData());
    verifyKeyUID(info.getKeyUID(), (ECPublicKey) keyPair.getPublic());

    if (cmdSet.getApplicationInfo().hasSecureChannelCapability()) {
      cmdSet.autoOpenSecureChannel();
    }

    if (cmdSet.getApplicationInfo().hasCredentialsManagementCapability()) {
      response = cmdSet.verifyPIN("000000");
      assertEquals(0x9000, response.getSw());
    }

    assertTrue(cmdSet.getKeyInitializationStatus());

    // Good case
    response = cmdSet.removeKey();
    assertEquals(0x9000, response.getSw());

    assertFalse(cmdSet.getKeyInitializationStatus());

    response = cmdSet.select();
    assertEquals(0x9000, response.getSw());
    info = new ApplicationInfo(response.getData());
    assertEquals(0, info.getKeyUID().length);
  }

  @Test
  @DisplayName("FACTORY RESET command")
  @Capabilities("factoryReset")
  void factoryResetTest() throws Exception {    
    // Invalid P1 P2
    APDUResponse response = sdkChannel.send(new APDUCommand(0x80, KeycardApplet.INS_FACTORY_RESET, 0, 0, new byte[0]));
    assertEquals(0x6a86, response.getSw());

    // Initialized card with a key, PIN not verified: refused, and nothing is wiped
    cmdSet.autoOpenSecureChannel();
    assertEquals(0x9000, cmdSet.verifyPIN("000000").getSw());
    assertEquals(0x9000, cmdSet.generateKey().getSw());
    resetAndSelectAndOpenSC();
    response = cmdSet.factoryReset();
    assertEquals(0x6985, response.getSw());
    assertTrue(cmdSet.getKeyInitializationStatus());

    // A wrong PIN does not help
    assertEquals(0x63c2, cmdSet.verifyPIN("999999").getSw());
    assertEquals(0x6985, cmdSet.factoryReset().getSw());

    // Duress (alt) PIN verified: allowed, so the duress PIN stays indistinguishable from the main PIN
    assertEquals(0x9000, cmdSet.verifyPIN("024680").getSw());
    response = cmdSet.factoryReset();
    assertEquals(0x9000, response.getSw());

    response = cmdSet.select();
    assertEquals(0x9000, response.getSw());
    assertFalse(cmdSet.getApplicationInfo().isInitializedCard());

    // Not initialized: allowed (nothing to protect)
    assertEquals(0x9000, cmdSet.factoryReset().getSw());
    cmdSet.select().checkOK();

    // PIN and PUK both blocked: the keys are already unusable, so a reset is allowed without a PIN
    initCard(cmdSet);
    cmdSet.autoOpenSecureChannel();
    for (int i = 0; i < 3; i++) {
      cmdSet.verifyPIN("999999");
    }
    assertEquals(0x6985, cmdSet.factoryReset().getSw()); // PUK still has tries left
    for (int i = 0; i < 5; i++) {
      cmdSet.unblockPIN("999999999999", "000000");
    }
    assertEquals(0x9000, cmdSet.factoryReset().getSw());
    cmdSet.select().checkOK();
    assertFalse(cmdSet.getApplicationInfo().isInitializedCard());

    // Main PIN verified: allowed (the good case)
    initCard(cmdSet);
    cmdSet.autoOpenSecureChannel();
    assertEquals(0x9000, cmdSet.verifyPIN("000000").getSw());
    response = cmdSet.factoryReset();
    assertEquals(0x9000, response.getSw());

    response = cmdSet.select();
    assertEquals(0x9000, response.getSw());
    assertFalse(cmdSet.getApplicationInfo().isInitializedCard());

    initCard(cmdSet);

    response = cmdSet.select();
    assertEquals(0x9000, response.getSw());

    if (cmdSet.getApplicationInfo().hasSecureChannelCapability()) {
      cmdSet.autoOpenSecureChannel();
    }

    if (cmdSet.getApplicationInfo().hasCredentialsManagementCapability()) {
      response = cmdSet.verifyPIN("000000");
      assertEquals(0x9000, response.getSw());
    }

    assertFalse(cmdSet.getKeyInitializationStatus());
  }

  @Test
  @DisplayName("GET CHALLENGE command")
  @Capabilities("secureChannel")
  void getChallengeWithSecureChannelTest() throws Exception {
    cmdSet.autoOpenSecureChannel();

    APDUResponse response = cmdSet.getChallenge(16);
    assertEquals(0x9000, response.getSw());
    assertEquals(16, response.getData().length);

    response = cmdSet.getChallenge(32);
    assertEquals(0x9000, response.getSw());
    assertEquals(32, response.getData().length);

    int maxSecureChannelChallengeLength = SecureChannelV2.SC_MAX_RESPONSE_LENGTH;

    response = cmdSet.getChallenge(maxSecureChannelChallengeLength);
    assertEquals(0x9000, response.getSw());
    assertEquals(maxSecureChannelChallengeLength, response.getData().length);

    response = cmdSet.getChallenge(maxSecureChannelChallengeLength + 1);
    assertEquals(0x6A86, response.getSw());

    response = cmdSet.getChallenge(255);
    assertEquals(0x6A86, response.getSw());
  }

  @Test
  @DisplayName("GENERATE KEY command")
  @Capabilities("keyManagement")
  void generateKeyTest() throws Exception {
    APDUResponse response;

    if (cmdSet.getApplicationInfo().hasSecureChannelCapability()) {
      // Security condition violation: SecureChannel not open
      response = cmdSet.generateKey();
      assertEquals(0x6985, response.getSw());
      cmdSet.autoOpenSecureChannel();
    }

    if (cmdSet.getApplicationInfo().hasCredentialsManagementCapability()) {
      // Security condition violation: PIN not verified
      response = cmdSet.generateKey();
      assertEquals(0x6985, response.getSw());

      response = cmdSet.verifyPIN("000000");
      assertEquals(0x9000, response.getSw());
    }

    // Good case
    response = cmdSet.generateKey();
    assertEquals(0x9000, response.getSw());
    byte[] keyUID = response.getData();

    response = cmdSet.exportKey(new byte[0], KeycardApplet.DERIVE_P1_SOURCE_MASTER, false, true);
    assertEquals(0x9000, response.getSw());
    byte[] pubKey = response.getData();

    verifyKeyUID(keyUID, Arrays.copyOfRange(pubKey, 4, pubKey.length));
  }


  @Test
  @DisplayName("SIGN command")
  void signTest() throws Exception {
    byte[] data = "some data to be hashed".getBytes();
    byte[] hash = sha256(data);

    APDUResponse response;

    if (cmdSet.getApplicationInfo().hasSecureChannelCapability()) {
      // Security condition violation: SecureChannel not open
      response = cmdSet.signWithPath(hash, "m", false);
      assertEquals(0x6985, response.getSw());

      cmdSet.autoOpenSecureChannel();
    }

    if (cmdSet.getApplicationInfo().hasCredentialsManagementCapability()) {
      // Security condition violation: PIN not verified
      response = cmdSet.signWithPath(hash, "m", false);
      assertEquals(0x6985, response.getSw());

      response = cmdSet.verifyPIN("000000");
      assertEquals(0x9000, response.getSw());
    }

    if (!cmdSet.getApplicationInfo().hasMasterKey()) {
      response = cmdSet.generateKey();
      assertEquals(0x9000, response.getSw());
    }

    // Correctly sign with master key (path "m" = master)
    response = cmdSet.signWithPath(hash, "m", false);
    verifySignResp(data, response);

    // Sign with derived path
    String derivedPath = "m/2";
    response = cmdSet.signWithPath(hash, derivedPath, false);
    verifySignResp(data, response);

    // Sign Schnorr
    if (TARGET != TARGET_SIMULATOR) {
      response = cmdSet.signWithPath(hash, derivedPath, KeycardCommandSet.SIGN_P2_BIP340_SCHNORR, false);
      verifySchnorrSignResp(data, response);
    }

    // Alt PIN
    response = cmdSet.verifyPIN("024680");
    assertEquals(0x9000, response.getSw());

    response = cmdSet.signWithPath(hash, derivedPath, false);
    verifySignResp(data, response);
  }

  @Test
  @DisplayName("SIGN command with Ed25519")
  void signEd25519Test() throws Exception {
    byte[] data = "some data to be hashed".getBytes();
    byte[] hash = sha256(data);
    String path = "m/44'/148'/0'";

    if (cmdSet.getApplicationInfo().hasSecureChannelCapability()) {
      cmdSet.autoOpenSecureChannel();
    }

    if (cmdSet.getApplicationInfo().hasCredentialsManagementCapability()) {
      APDUResponse pinResponse = cmdSet.verifyPIN("000000");
      assertEquals(0x9000, pinResponse.getSw());
    }

    if (!cmdSet.getApplicationInfo().hasMasterKey()) {
      APDUResponse genResponse = cmdSet.generateKey();
      assertEquals(0x9000, genResponse.getSw());
    }

    APDUResponse response = cmdSet.signWithPath(hash, path, KeycardCommandSet.SIGN_P2_EDDSA_ED25519, false);
    assertEquals(0x9000, response.getSw());
    byte[] respData = response.getData();

    byte[] pubKey = extractPublicKeyFromSignature(respData);
    assertEquals(32, pubKey.length);

    byte[] sigTlv = extractSignature(respData);
    assertEquals((byte) 0x88, sigTlv[0]);
    assertEquals((byte) 64, sigTlv[1]);
    byte[] sig = Arrays.copyOfRange(sigTlv, 2, 66);

    // RFC 8032 verification against the returned public key
    Ed25519Signer verifier = new Ed25519Signer();
    verifier.init(false, new Ed25519PublicKeyParameters(pubKey, 0));
    verifier.update(hash, 0, hash.length);
    assertTrue(verifier.verifySignature(sig), "Ed25519 signature must verify");

    // pure Ed25519 is deterministic: same key, same message => same signature
    APDUResponse response2 = cmdSet.signWithPath(hash, path, KeycardCommandSet.SIGN_P2_EDDSA_ED25519, false);
    assertEquals(0x9000, response2.getSw());
    assertArrayEquals(respData, response2.getData(), "Ed25519 signing must be deterministic");

    // a different message must verify too (fresh nonce path)
    byte[] hash2 = sha256("something else".getBytes());
    response = cmdSet.signWithPath(hash2, path, KeycardCommandSet.SIGN_P2_EDDSA_ED25519, false);
    assertEquals(0x9000, response.getSw());
    assertArrayEquals(pubKey, extractPublicKeyFromSignature(response.getData()), "same path => same pubkey");
    sig = Arrays.copyOfRange(extractSignature(response.getData()), 2, 66);
    verifier = new Ed25519Signer();
    verifier.init(false, new Ed25519PublicKeyParameters(pubKey, 0));
    verifier.update(hash2, 0, hash2.length);
    assertTrue(verifier.verifySignature(sig), "second Ed25519 signature must verify");

    // ECDSA on the same derived path still works
    response = cmdSet.signWithPath(hash, path, false);
    verifySignResp(data, response);
  }

  @Test
  @DisplayName("SLIP-0010 Ed25519 derivation matches SEP-0005 test vector")
  void stellarSep0005Test() throws Exception {
    // SEP-0005 test vector 1: 12-word mnemonic, primary account m/44'/148'/0'
    String mnemonic = "illness spike retreat truth genius clock brain pass fit cave bargain toe";
    String expectedAddress = "GDRXE2BQUC3AZNPVFSCEZ76NJ3WWL25FYFK6RGZGIEKWE4SOOHSUJUJ6";
    byte[] expectedPub = decodeStrkey(expectedAddress);

    byte[] seed = MnemonicCode.toSeed(Arrays.asList(mnemonic.split(" ")), "");
    byte[] stellarPath = {
        (byte) 0x80, 0x00, 0x00, 0x2C, // 44'
        (byte) 0x80, 0x00, 0x00, (byte) 0x94, // 148'
        (byte) 0x80, 0x00, 0x00, 0x00  // 0'
    };

    if (cmdSet.getApplicationInfo().hasSecureChannelCapability()) {
      cmdSet.autoOpenSecureChannel();
    }

    if (cmdSet.getApplicationInfo().hasCredentialsManagementCapability()) {
      APDUResponse pinResponse = cmdSet.verifyPIN("000000");
      assertEquals(0x9000, pinResponse.getSw());
    }

    APDUResponse response = cmdSet.loadKey(seed);
    assertEquals(0x9000, response.getSw());

    // EXPORT KEY with P2 = ED25519 public
    response = cmdSet.exportKey(stellarPath, KeycardApplet.DERIVE_P1_SOURCE_MASTER, false, KeycardApplet.EXPORT_KEY_P2_ED25519_PUBLIC);
    assertEquals(0x9000, response.getSw());
    byte[] keyTemplate = response.getData();
    assertEquals(KeycardApplet.TLV_KEY_TEMPLATE, keyTemplate[0]);
    assertEquals(KeycardApplet.TLV_PUB_KEY, keyTemplate[2]);
    assertEquals(32, keyTemplate[3]);
    byte[] exportedPub = Arrays.copyOfRange(keyTemplate, 4, 36);
    assertArrayEquals(expectedPub, exportedPub, "exported pubkey must match SEP-0005 G-address");

    // SIGN with the same path must report the same pubkey and produce a valid signature
    byte[] hash = sha256("stellar transaction signature payload".getBytes());
    response = cmdSet.signWithPath(hash, "m/44'/148'/0'", KeycardCommandSet.SIGN_P2_EDDSA_ED25519, false);
    assertEquals(0x9000, response.getSw());
    byte[] signPub = extractPublicKeyFromSignature(response.getData());
    assertArrayEquals(expectedPub, signPub, "SIGN pubkey must match SEP-0005 G-address");

    byte[] sig = Arrays.copyOfRange(extractSignature(response.getData()), 2, 66);
    Ed25519Signer verifier = new Ed25519Signer();
    verifier.init(false, new Ed25519PublicKeyParameters(expectedPub, 0));
    verifier.update(hash, 0, hash.length);
    assertTrue(verifier.verifySignature(sig), "Ed25519 signature must verify against SEP-0005 key");

    // non-hardened path elements are invalid for ed25519 (SW_DATA_INVALID, same as failed BIP32 derivation)
    response = cmdSet.signWithPath(hash, "m/44'/148'/0", KeycardCommandSet.SIGN_P2_EDDSA_ED25519, false);
    assertEquals(0x6984, response.getSw());
  }

  @Test
  @DisplayName("the duress PIN derives a separate (decoy) set of Ed25519 keys; the main PIN still gets SEP-0005")
  @Capabilities("credentialsManagement")
  void ed25519DuressTreeTest() throws Exception {
    String mnemonic = "illness spike retreat truth genius clock brain pass fit cave bargain toe";
    byte[] expectedPub = decodeStrkey("GDRXE2BQUC3AZNPVFSCEZ76NJ3WWL25FYFK6RGZGIEKWE4SOOHSUJUJ6");
    byte[] seed = MnemonicCode.toSeed(Arrays.asList(mnemonic.split(" ")), "");
    byte[] stellarPath = {(byte) 0x80, 0x00, 0x00, 0x2C, (byte) 0x80, 0x00, 0x00, (byte) 0x94, (byte) 0x80, 0x00, 0x00, 0x00};
    byte[] hash = sha256("duress tree".getBytes());

    cmdSet.autoOpenSecureChannel();
    assertEquals(0x9000, cmdSet.verifyPIN("000000").getSw());
    assertEquals(0x9000, cmdSet.loadKey(seed).getSw());
    assertArrayEquals(expectedPub, exportEd25519(stellarPath));

    // duress PIN: a different key at the same path, and SIGN agrees with EXPORT inside the decoy tree
    assertEquals(0x9000, cmdSet.verifyPIN("024680").getSw());
    byte[] decoyPub = exportEd25519(stellarPath);
    assertFalse(Arrays.equals(expectedPub, decoyPub), "the duress PIN must not reach the real Ed25519 keys");
    APDUResponse response = cmdSet.signWithPath(hash, "m/44'/148'/0'", KeycardCommandSet.SIGN_P2_EDDSA_ED25519, false);
    assertEquals(0x9000, response.getSw());
    assertArrayEquals(decoyPub, extractPublicKeyFromSignature(response.getData()));
    Ed25519Signer verifier = new Ed25519Signer();
    verifier.init(false, new Ed25519PublicKeyParameters(decoyPub, 0));
    verifier.update(hash, 0, hash.length);
    assertTrue(verifier.verifySignature(Arrays.copyOfRange(extractSignature(response.getData()), 2, 66)));

    // the empty path would be the master key, the same in both trees: refused for both PINs
    response = cmdSet.exportKey(new byte[0], KeycardApplet.DERIVE_P1_SOURCE_MASTER, false, KeycardApplet.EXPORT_KEY_P2_ED25519_PUBLIC);
    assertEquals(0x6A80, response.getSw());
    assertEquals(0x9000, cmdSet.verifyPIN("000000").getSw());
    response = cmdSet.exportKey(new byte[0], KeycardApplet.DERIVE_P1_SOURCE_MASTER, false, KeycardApplet.EXPORT_KEY_P2_ED25519_PUBLIC);
    assertEquals(0x6A80, response.getSw());

    // back on the main PIN: the real key again
    assertArrayEquals(expectedPub, exportEd25519(stellarPath));
  }

  @Test
  @DisplayName("LOAD KEY with a 16- or 32-byte seed (e.g. a SLIP-39 master secret) gets the Ed25519 tree")
  @Capabilities("credentialsManagement")
  void ed25519ShortSeedTest() throws Exception {
    cmdSet.autoOpenSecureChannel();
    assertEquals(0x9000, cmdSet.verifyPIN("000000").getSw());

    // SLIP-0010 test vector 1 (ed25519): seed 000102...0f, m/0' public key
    byte[] vectorSeed = Hex.decode("000102030405060708090a0b0c0d0e0f");
    assertEquals(0x9000, cmdSet.loadKey(vectorSeed).getSw());
    assertArrayEquals(Hex.decode("8c8a13df77a28f3445213a0f432fde644acaa215fc72dcdf300d5efaa85d350c"),
        exportEd25519(new byte[] {(byte) 0x80, 0x00, 0x00, 0x00}), "SLIP-0010 vector 1, m/0'");

    // 16- and 32-byte seeds against an independent SLIP-0010 derivation, at a Stellar path
    int[] path = {0x8000002C, 0x80000094, 0x80000003};
    byte[] pathBytes = new byte[path.length * 4];
    for (int i = 0; i < path.length; i++) {
      pathBytes[i * 4] = (byte) (path[i] >> 24);
      pathBytes[i * 4 + 1] = (byte) (path[i] >> 16);
      pathBytes[i * 4 + 2] = (byte) (path[i] >> 8);
      pathBytes[i * 4 + 3] = (byte) path[i];
    }
    for (int len : new int[] {16, 32}) {
      byte[] seed = new byte[len];
      new java.security.SecureRandom().nextBytes(seed);
      assertEquals(0x9000, cmdSet.loadKey(seed).getSw());
      assertArrayEquals(slip10Ed25519Public(seed, path), exportEd25519(pathBytes), len + "-byte seed");
    }
  }

  /** SLIP-0010 ed25519, hardened only, computed with BouncyCastle (independent of the applet). */
  private static byte[] slip10Ed25519Public(byte[] seed, int[] path) {
    org.bouncycastle.crypto.macs.HMac hmac = new org.bouncycastle.crypto.macs.HMac(new org.bouncycastle.crypto.digests.SHA512Digest());
    byte[] i = new byte[64];
    hmac.init(new org.bouncycastle.crypto.params.KeyParameter("ed25519 seed".getBytes(java.nio.charset.StandardCharsets.US_ASCII)));
    hmac.update(seed, 0, seed.length);
    hmac.doFinal(i, 0);
    for (int index : path) {
      byte[] data = new byte[37];
      System.arraycopy(i, 0, data, 1, 32);
      data[33] = (byte) (index >> 24);
      data[34] = (byte) (index >> 16);
      data[35] = (byte) (index >> 8);
      data[36] = (byte) index;
      hmac.init(new org.bouncycastle.crypto.params.KeyParameter(Arrays.copyOfRange(i, 32, 64)));
      hmac.update(data, 0, data.length);
      hmac.doFinal(i, 0);
    }
    return new org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters(i, 0).generatePublicKey().getEncoded();
  }

  private byte[] exportEd25519(byte[] path) throws Exception {
    APDUResponse response = cmdSet.exportKey(path, KeycardApplet.DERIVE_P1_SOURCE_MASTER, false, KeycardApplet.EXPORT_KEY_P2_ED25519_PUBLIC);
    assertEquals(0x9000, response.getSw());
    return Arrays.copyOfRange(response.getData(), 4, 36);
  }

  private byte[] decodeStrkey(String address) {
    byte[] raw = new Base32().decode(address);
    // version byte (1) || ed25519 public key (32) || CRC16 (2)
    assertEquals(35, raw.length);
    assertEquals((byte) (6 << 3), raw[0]);
    return Arrays.copyOfRange(raw, 1, 33);
  }

  private void verifySchnorrSignResp(byte[] data, APDUResponse response) throws Exception {
    assertEquals(0x9000, response.getSw());
    byte[] sig = response.getData();
    byte[] keyData = extractPublicKeyFromSignature(sig);
    sig = extractSignature(sig);

    assertEquals(65, keyData.length);
    assertEquals((byte) 4, keyData[0]);
    assertEquals(66, sig.length);
    assertEquals((byte) 0x88, sig[0]);
    assertEquals((byte) 64, sig[1]);
  }

  private void verifySignResp(byte[] data, APDUResponse response) throws Exception {
    Signature signature = Signature.getInstance("SHA256withECDSA", "BC");
    assertEquals(0x9000, response.getSw());
    byte[] sig = response.getData();
    byte[] keyData = extractPublicKeyFromSignature(sig);
    sig = extractSignature(sig);

    ECParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec("secp256k1");
    ECPublicKeySpec cardKeySpec = new ECPublicKeySpec(ecSpec.getCurve().decodePoint(keyData), ecSpec);
    ECPublicKey cardKey = (ECPublicKey) KeyFactory.getInstance("ECDSA", "BC").generatePublic(cardKeySpec);

    signature.initVerify(cardKey);
    assertEquals(65, keyData.length);
    signature.update(data);
    assertTrue(signature.verify(sig));
    assertFalse(isMalleable(sig));
  }

  @Test
  @DisplayName("EXPORT KEY command")
  void exportKey() throws Exception {
    KeyPairGenerator g = keypairGenerator();
    KeyPair keyPair = g.generateKeyPair();
    byte[] chainCode = new byte[32];
    new Random().nextBytes(chainCode);

    APDUResponse response;

    if (cmdSet.getApplicationInfo().hasSecureChannelCapability()) {
      // Security condition violation: SecureChannel not open
      response = cmdSet.exportKey(new byte[0], KeycardApplet.DERIVE_P1_SOURCE_MASTER, false, true);
      assertEquals(0x6985, response.getSw());

      cmdSet.autoOpenSecureChannel();
    }

    if (cmdSet.getApplicationInfo().hasCredentialsManagementCapability()) {
      // Security condition violation: PIN not verified
      response = cmdSet.exportKey(new byte[0], KeycardApplet.DERIVE_P1_SOURCE_MASTER, false, true);
      assertEquals(0x6985, response.getSw());

      response = cmdSet.verifyPIN("000000");
      assertEquals(0x9000, response.getSw());
    }

    if (cmdSet.getApplicationInfo().hasKeyManagementCapability()) {
      response = cmdSet.loadKey(keyPair, false, chainCode);
      assertEquals(0x9000, response.getSw());
    }

    // Export master public key (empty path)
    response = cmdSet.exportKey(new byte[0], KeycardApplet.DERIVE_P1_SOURCE_MASTER, false, true);
    assertEquals(0x9000, response.getSw());
    byte[] keyTemplate = response.getData();
    verifyExportedKey(keyTemplate, keyPair, chainCode, new int[0], true, false);

    // Export derived public key
    response = cmdSet.exportKey(new byte[] {(byte) 0x80, 0x00, 0x00, 0x2B, (byte) 0x80, 0x00, 0x00, 0x3C, (byte) 0x80, 0x00, 0x06, 0x2D, (byte) 0x00, 0x00, 0x00, 0x00}, KeycardApplet.DERIVE_P1_SOURCE_MASTER, false, true);
    assertEquals(0x9000, response.getSw());
    keyTemplate = response.getData();
    verifyExportedKey(keyTemplate, keyPair, chainCode, new int[] { 0x8000002b, 0x8000003c, 0x8000062d, 0x00000000 }, true, false);

    // Export derived private key
    response = cmdSet.exportKey(new byte[] {(byte) 0x80, 0x00, 0x00, 0x2B, (byte) 0x80, 0x00, 0x00, 0x3C, (byte) 0x80, 0x00, 0x06, 0x2D, (byte) 0x00, 0x00, 0x00, 0x00}, KeycardApplet.DERIVE_P1_SOURCE_MASTER, false, false);
    assertEquals(0x6985, response.getSw());

    // Export derived private key (EIP-1581 path)
    response = cmdSet.exportKey(new byte[] {(byte) 0x80, 0x00, 0x00, 0x2B, (byte) 0x80, 0x00, 0x00, 0x3C, (byte) 0x80, 0x00, 0x06, 0x2D, (byte) 0x00, 0x00, 0x00, 0x00, (byte) 0x00, 0x00, 0x00, 0x00}, KeycardApplet.DERIVE_P1_SOURCE_MASTER, false, false);
    assertEquals(0x9000, response.getSw());
    keyTemplate = response.getData();
    verifyExportedKey(keyTemplate, keyPair, chainCode, new int[] { 0x8000002b, 0x8000003c, 0x8000062d, 0x00000000, 0x00000000 }, false, false);

    // Export extended public key
    response = cmdSet.exportKey(new byte[] {(byte) 0x80, 0x00, 0x00, 0x2B, (byte) 0x80, 0x00, 0x00, 0x3C, (byte) 0x80, 0x00, 0x06, 0x2c, (byte) 0x00, 0x00, 0x00, 0x00}, KeycardApplet.DERIVE_P1_SOURCE_MASTER, false, KeycardCommandSet.EXPORT_KEY_P2_EXTENDED_PUBLIC);
    assertEquals(0x9000, response.getSw());
    keyTemplate = response.getData();
    verifyExportedKey(keyTemplate, keyPair, chainCode, new int[] { 0x8000002b, 0x8000003c, 0x8000062c, 0x00000000 }, true, true);

    // Alt PIN
    response = cmdSet.verifyPIN("024680");
    assertEquals(0x9000, response.getSw());

    response = cmdSet.exportKey(new byte[] {(byte) 0x80, 0x00, 0x00, 0x2B, (byte) 0x80, 0x00, 0x00, 0x3C, (byte) 0x80, 0x00, 0x06, 0x2c, (byte) 0x00, 0x00, 0x00, 0x00}, KeycardApplet.DERIVE_P1_SOURCE_MASTER, false, KeycardCommandSet.EXPORT_KEY_P2_EXTENDED_PUBLIC);
    assertEquals(0x9000, response.getSw());
    keyTemplate = response.getData();
    verifyExportedKey(keyTemplate, keyPair, sha256(chainCode), new int[] { 0x8000002b, 0x8000003c, 0x8000062c, 0x00000000 }, true, true);
  }

  @Test
  @DisplayName("LEE Keys")
  void leeKeysTest() throws Exception {
    byte[] seed = Mnemonic.toBinarySeed("fan empower output between game genius forest bulk party small arm shuffle", "");
    byte[] expectedPublic = Hex.decode("045bdbe46824409ae66c960f4a204ac66adc1646dcfa56a5b455629f99b95a643012390c799fb8a1f5e9140dfe9f6088ab1ded90f496c9d8832df501e3c8e9c45f");
    byte[] expectedNsk = Hex.decode("a44386392e2112c8c46a7f8378b4c3163011a76664a2b1d23e25a6f35ef90739");
    byte[] expectedVsk = Hex.decode("d06cc239011a56c8aecec0579b884227d637496a6e3e8f27d70e170f2ec3fa0d97dc323114bb420ef3061010446a9b4cf321ebc895ac8b7f261e3fbcaef79a67");

    cmdSet.autoOpenSecureChannel();
    APDUResponse response = cmdSet.verifyPIN("000000");
    assertEquals(0x9000, response.getSw());

    response = cmdSet.loadLEEKey(seed);
    assertEquals(0x9000, response.getSw());

    response = cmdSet.exportKey(new byte[] {(byte) 0x80, 0x00, 0x00, 0x2B, (byte) 0x80, 0x00, 0x00, 0x3C}, KeycardApplet.DERIVE_P1_SOURCE_MASTER, false, true);
    assertEquals(0x9000, response.getSw());
    BIP32KeyPair pair = BIP32KeyPair.fromTLV(response.getData());
    assertArrayEquals(expectedPublic, pair.getPublicKey());

    if (TARGET != TARGET_SIMULATOR) {
      response = cmdSet.exportLEEKey(new byte[] {(byte) 0x80, 0x00, 0x00, 0x2B, (byte) 0x80, 0x00, 0x00, 0x3C}, KeycardApplet.DERIVE_P1_SOURCE_MASTER);
      assertEquals(0x9000, response.getSw());
      TinyBERTLV tlvReader = new TinyBERTLV(response.getData());
      tlvReader.enterConstructed(KeycardApplet.TLV_KEY_TEMPLATE);
      assertArrayEquals(expectedNsk, tlvReader.readPrimitive(KeycardApplet.TLV_LEE_NSK));
      assertArrayEquals(expectedVsk, tlvReader.readPrimitive(KeycardApplet.TLV_LEE_VSK));      
    }
  }

  @Test
  @DisplayName("BIP85")
  void bip85Test() throws Exception {    
    byte[] expectedData = Hex.decode("efecfbccffea313214232d29e71563d941229afb4338c21f9517c41aaa0d16f00b83d2a09ef747e7a64e8e2bd5a14869e693da66ce94ac2da570ab7ee48618f7");

    cmdSet.autoOpenSecureChannel();
    
    APDUResponse response = cmdSet.verifyPIN("000000");
    assertEquals(0x9000, response.getSw());

    response = cmdSet.loadKey(new BIP32KeyPair(Hex.decode("3f15e5d852dc2e9ba5e9fe189a8dd2e1547badef5b563bbe6579fc6807d80ed9"), Hex.decode("1b67969d1ec69bdfeeae43213da8460ba34b92d0788c8f7bfcfa44906e8a589c"), null));
    assertEquals(0x9000, response.getSw());

    response = cmdSet.exportBIP85(64, new KeyPath("m/83696968'/0'/0'").getData());
    assertEquals(0x9000, response.getSw());
    assertArrayEquals(expectedData, response.getData());
  }

  // Published BIP85 master key (bip-0085.mediawiki, "Test vectors"), decoded here rather than transcribed.
  static final String BIP85_XPRV = "xprv9s21ZrQH143K2LBWUUQRFXhucrQqBpKdRRxNVq2zBqsx8HVqFk2uYo8kmbaLLHRdqtQpUm98uKfu3vca1LqdGhUtyoFnCNkfmXRyPXLjbKb";

  /**
   * Independent BIP85: BIP32 derivation by bitcoinj, then HMAC-SHA512("bip-entropy-from-k", k) by
   * BouncyCastle, truncated to len bytes. Shares no code with the applet.
   */
  static DeterministicKey bip32Derive(DeterministicKey master, String path) {
    DeterministicKey k = master;
    for (String c : path.substring(2).split("/")) {
      boolean hardened = c.endsWith("'");
      long idx = Long.parseLong(hardened ? c.substring(0, c.length() - 1) : c);
      k = HDKeyDerivation.deriveChildKey(k, new ChildNumber((int) idx, hardened));
    }
    return k;
  }

  static byte[] bip85Reference(DeterministicKey master, String path, int len) {
    DeterministicKey k = bip32Derive(master, path);
    org.bouncycastle.crypto.macs.HMac hmac = new org.bouncycastle.crypto.macs.HMac(new org.bouncycastle.crypto.digests.SHA512Digest());
    hmac.init(new org.bouncycastle.crypto.params.KeyParameter("bip-entropy-from-k".getBytes(java.nio.charset.StandardCharsets.US_ASCII)));
    byte[] priv = k.getPrivKeyBytes();
    hmac.update(priv, 0, priv.length);
    byte[] out = new byte[64];
    hmac.doFinal(out, 0);
    return Arrays.copyOf(out, len);
  }

  static DeterministicKey bip85Master() {
    return DeterministicKey.deserializeB58(null, BIP85_XPRV, org.bitcoinj.params.MainNetParams.get());
  }

  void loadBip85Master(DeterministicKey master) throws Exception {
    cmdSet.autoOpenSecureChannel();
    assertEquals(0x9000, cmdSet.verifyPIN("000000").getSw());
    assertEquals(0x9000, cmdSet.loadKey(new BIP32KeyPair(master.getPrivKeyBytes(), master.getChainCode(), null)).getSw());
  }

  byte[] cardBip85(String path, int len) throws Exception {
    APDUResponse response = cmdSet.exportBIP85(len, new KeyPath(path).getData());
    assertEquals(0x9000, response.getSw(), path + " len " + len);
    return response.getData();
  }

  @Test
  @DisplayName("BIP85 published vectors: both raw cases and the 12/18/24-word BIP39 application, to the word")
  void bip85PublishedVectorsTest() throws Exception {
    DeterministicKey master = bip85Master();

    // The reference implementation must reproduce the published derived keys before it is trusted
    assertEquals("cca20ccb0e9a90feb0912870c3323b24874b0ca3d8018c4b96d0b97c0e82ded0",
        Hex.toHexString(bip32Derive(master, "m/83696968'/0'/0'").getPrivKeyBytes()));
    assertEquals("503776919131758bb7de7beb6c0ae24894f4ec042c26032890c29359216e21ba",
        Hex.toHexString(bip32Derive(master, "m/83696968'/0'/1'").getPrivKeyBytes()));

    loadBip85Master(master);

    String[][] raw = {
        {"m/83696968'/0'/0'", "efecfbccffea313214232d29e71563d941229afb4338c21f9517c41aaa0d16f00b83d2a09ef747e7a64e8e2bd5a14869e693da66ce94ac2da570ab7ee48618f7"},
        {"m/83696968'/0'/1'", "70c6e3e8ebee8dc4c0dbba66076819bb8c09672527c4277ca8729532ad711872218f826919f6b67218adde99018a6df9095ab2b58d803b5b93ec9802085a690e"}};
    for (String[] v : raw) {
      assertEquals(v[1], Hex.toHexString(cardBip85(v[0], 64)), v[0]);
      assertEquals(v[1], Hex.toHexString(bip85Reference(master, v[0], 64)), "reference " + v[0]);
    }

    // BIP39 application, English (language 0'): entropy truncated to 16/24/32 bytes
    String[][] bip39 = {
        {"12", "6250b68daf746d12a24d58b4787a714b", "girl mad pet galaxy egg matter matrix prison refuse sense ordinary nose"},
        {"18", "938033ed8b12698449d4bbca3c853c66b293ea1b1ce9d9dc", "near account window bike charge season chef number sketch tomorrow excuse sniff circle vital hockey outdoor supply token"},
        {"24", "ae131e2312cdc61331542efe0d1077bac5ea803adf24b313a4f0e48e9c51f37f", "puppy ocean match cereal symbol another shed magic wrap hammer bulb intact gadget divorce twin tonight reason outdoor destroy simple truth cigar social volcano"}};
    for (String[] v : bip39) {
      String path = "m/83696968'/39'/0'/" + v[0] + "'/0'";
      int len = Integer.parseInt(v[0]) * 4 / 3;
      byte[] entropy = cardBip85(path, len);
      assertEquals(v[1], Hex.toHexString(entropy), path);
      assertEquals(v[2], String.join(" ", MnemonicCode.INSTANCE.toMnemonic(entropy)), path + " mnemonic");
    }
  }

  @Test
  @DisplayName("BIP85 card vs independent reference: many paths, indexes, depths and every output length")
  void bip85CrossCheckTest() throws Exception {
    DeterministicKey master = bip85Master();
    loadBip85Master(master);

    java.util.List<String[]> cases = new java.util.ArrayList<>();
    for (String words : new String[] {"12", "18", "24"}) {
      for (String index : new String[] {"0", "1", "2", "1000", "2147483647"}) {
        cases.add(new String[] {"m/83696968'/39'/0'/" + words + "'/" + index + "'", Integer.toString(Integer.parseInt(words) * 4 / 3)});
      }
    }
    cases.add(new String[] {"m/83696968'/39'/1'/12'/0'", "16"});          // non-English language code
    cases.add(new String[] {"m/83696968'/2'/0'", "32"});                  // WIF
    cases.add(new String[] {"m/83696968'/32'/0'", "64"});                 // XPRV
    for (String bytes : new String[] {"16", "32", "64"}) {
      cases.add(new String[] {"m/83696968'/128169'/" + bytes + "'/0'", bytes}); // HEX
    }
    cases.add(new String[] {"m/83696968'/1'/2'/3'/4'/5'/6'/7'/8'/9'", "64"}); // maximum depth (10)

    for (String[] c : cases) {
      int len = Integer.parseInt(c[1]);
      assertArrayEquals(bip85Reference(master, c[0], len), cardBip85(c[0], len), c[0]);
    }

    // Truncation keeps the leading bytes, for every allowed length
    byte[] full = bip85Reference(master, "m/83696968'/0'/0'", 64);
    for (int len = 1; len <= 64; len++) {
      assertArrayEquals(Arrays.copyOf(full, len), cardBip85("m/83696968'/0'/0'", len), "len " + len);
    }
  }

  @Test
  @DisplayName("BIP85 from a seed loaded with LOAD KEY P1=SEED matches the reference (the production path)")
  void bip85FromSeedTest() throws Exception {
    // A BIP85-derived phrase used as a root, as the recovery flow would
    String phrase = "girl mad pet galaxy egg matter matrix prison refuse sense ordinary nose";
    byte[] seed = MnemonicCode.toSeed(Arrays.asList(phrase.split(" ")), "");
    DeterministicKey master = HDKeyDerivation.createMasterPrivateKey(seed);

    cmdSet.autoOpenSecureChannel();
    assertEquals(0x9000, cmdSet.verifyPIN("000000").getSw());
    assertEquals(0x9000, cmdSet.loadKey(seed).getSw());

    for (String path : new String[] {"m/83696968'/39'/0'/12'/0'", "m/83696968'/39'/0'/24'/3'", "m/83696968'/0'/0'"}) {
      int len = path.contains("/12'/") ? 16 : path.contains("/24'/") ? 32 : 64;
      assertArrayEquals(bip85Reference(master, path, len), cardBip85(path, len), path);
    }
  }

  @Test
  @DisplayName("BIP85 rejects non-hardened components, foreign roots, too-deep paths and bad lengths")
  void bip85RejectsTest() throws Exception {
    loadBip85Master(bip85Master());

    assertEquals(0x6a80, cmdSet.exportBIP85(16, new KeyPath("m/83696968'/39'/0'/12'/0").getData()).getSw());
    assertEquals(0x6a80, cmdSet.exportBIP85(16, new KeyPath("m/83696968'/39/0'/12'/0'").getData()).getSw());
    assertEquals(0x6a80, cmdSet.exportBIP85(16, new KeyPath("m/44'/39'/0'/12'/0'").getData()).getSw());
    assertEquals(0x6a80, cmdSet.exportBIP85(16, new KeyPath("m/83696968'").getData()).getSw());
    // 11 hardened components, one past KEY_PATH_MAX_DEPTH; built by hand because KeyPath refuses it
    ByteBuffer tooDeep = ByteBuffer.allocate(11 * 4);
    tooDeep.putInt(0x80000000 | 83696968);
    for (int i = 1; i <= 10; i++) {
      tooDeep.putInt(0x80000000 | i);
    }
    assertNotEquals(0x9000, cmdSet.exportBIP85(64, tooDeep.array()).getSw());
    assertEquals(0x6a86, cmdSet.exportBIP85(0, new KeyPath("m/83696968'/0'/0'").getData()).getSw());
    assertEquals(0x6a86, cmdSet.exportBIP85(65, new KeyPath("m/83696968'/0'/0'").getData()).getSw());
  }

  @Test
  @DisplayName("STORE/GET DATA")
  void storeGetDataTest() throws Exception {
    APDUResponse response;

    if (cmdSet.getApplicationInfo().hasSecureChannelCapability()) {
      // Security condition violation: SecureChannel not open
      response = cmdSet.storeData(new byte[20], KeycardCommandSet.STORE_DATA_P1_PUBLIC);
      assertEquals(0x6985, response.getSw());

      cmdSet.autoOpenSecureChannel();
    }

    if (cmdSet.getApplicationInfo().hasCredentialsManagementCapability()) {
      // Security condition violation: PIN not verified
      response = cmdSet.storeData(new byte[20], KeycardCommandSet.STORE_DATA_P1_PUBLIC);
      assertEquals(0x6985, response.getSw());

      response = cmdSet.verifyPIN("000000");
      assertEquals(0x9000, response.getSw());
    }

    // Data too long
    response = cmdSet.storeData(new byte[128], KeycardCommandSet.STORE_DATA_P1_PUBLIC);
    assertEquals(0x6A80, response.getSw());

    byte[] data = new byte[127];

    for (int i = 0; i < 127; i++) {
      data[i] = (byte) i;
    }

    // Correct data
    response = cmdSet.storeData(data, KeycardCommandSet.STORE_DATA_P1_PUBLIC);

    assertEquals(0x9000, response.getSw());

    // Read data back with secure channel
    response = cmdSet.getData(KeycardCommandSet.STORE_DATA_P1_PUBLIC);
    assertEquals(0x9000, response.getSw());
    assertArrayEquals(data, response.getData());

    // Empty data
    response = cmdSet.storeData(new byte[0], KeycardCommandSet.STORE_DATA_P1_PUBLIC);
    assertEquals(0x9000, response.getSw());

    response = cmdSet.getData(KeycardCommandSet.STORE_DATA_P1_PUBLIC);
    assertEquals(0x9000, response.getSw());
    assertEquals(0, response.getData().length);

    // Shorter data
    data = Arrays.copyOf(data, 20);
    response = cmdSet.storeData(data, KeycardCommandSet.STORE_DATA_P1_PUBLIC);
    assertEquals(0x9000, response.getSw());

    // GET DATA without Secure Channel
    cmdSet.select().checkOK();
    response = cmdSet.getData(KeycardCommandSet.STORE_DATA_P1_PUBLIC);
    assertEquals(0x6985, response.getSw());

    if (cmdSet.getApplicationInfo().hasNDEFCapability()) {
      byte[] ndefData = {
              (byte) 0x00, (byte) 0x24, (byte) 0xd4, (byte) 0x0f, (byte) 0x12, (byte) 0x61, (byte) 0x6e, (byte) 0x64,
              (byte) 0x72, (byte) 0x6f, (byte) 0x69, (byte) 0x64, (byte) 0x2e, (byte) 0x63, (byte) 0x6f, (byte) 0x6d,
              (byte) 0x3a, (byte) 0x70, (byte) 0x6b, (byte) 0x67, (byte) 0x69, (byte) 0x6d, (byte) 0x2e, (byte) 0x73,
              (byte) 0x74, (byte) 0x61, (byte) 0x74, (byte) 0x75, (byte) 0x73, (byte) 0x2e, (byte) 0x65, (byte) 0x74,
              (byte) 0x68, (byte) 0x65, (byte) 0x72, (byte) 0x65, (byte) 0x75, (byte) 0x6d
      };

      // Security condition violation: SecureChannel not open
      response = cmdSet.setNDEF(ndefData);
      assertEquals(0x6985, response.getSw());

      cmdSet.autoOpenSecureChannel();

      // Security condition violation: PIN not verified
      response = cmdSet.setNDEF(ndefData);
      assertEquals(0x6985, response.getSw());

      response = cmdSet.verifyPIN("000000");
      assertEquals(0x9000, response.getSw());

      // Good case.
      response = cmdSet.setNDEF(ndefData);
      assertEquals(0x9000, response.getSw());

      // Good case with no length.
      response = cmdSet.setNDEF(Arrays.copyOfRange(ndefData, 2, ndefData.length));
      assertEquals(0x9000, response.getSw());

      // Long message with segmentation
      response = cmdSet.setNDEF(Hex.decode("c101000001b45402656e5468697320697320612072656c61746976656c79206c6f6e672074657874207265636f72642074686174206669747320696e2061626f75742035303020627974657320736f207468617420492063616e2074657374207365676d656e746174696f6e206f66207265636f726473207573696e6720746865206e657720616e6420696d70726f766564204e444546206170706c65742e20546869732069732071756974652061206c6f6e67207465787420746f2077726974652062757420686579204920616d206865726520666f7220746869732e204920776f6e277420636f707920616e64207061737465207468652073616d6520737472696e67206f76657220616e64206f766572206265636175736520492077616e7420746f206d616b6520737572652064617461206973207265616420636f72726563746c7920616e6420746865726520617265206e6f20737472616e67652073746974636865732e2049276420616c736f206c696b6520746f206d616b6520737572652065766572797468696e6720697320617320636c6f736520746f207265616c20776f726c6420757361676520617320706f737369626c65"));
      assertEquals(0x9000, response.getSw());
    }

    data[0] = (byte) 0xAA;

    response = cmdSet.storeData(data, KeycardCommandSet.STORE_DATA_P1_CASH);
    assertEquals(0x9000, response.getSw());

    CashCommandSet cashCmdSet = new CashCommandSet(sdkChannel);
    response = cashCmdSet.select();
    assertEquals(0x9000, response.getSw());
    CashApplicationInfo info = new CashApplicationInfo(response.getData());
    assertArrayEquals(data, info.getPubData());
  }

  @Test
  @DisplayName("GET DATA NDEF with output segmentation")
  @Capabilities("ndef")
  void getDataNdefSegmentationTest() throws Exception {
    cmdSet.autoOpenSecureChannel();

    APDUResponse response = cmdSet.verifyPIN("000000");
    assertEquals(0x9000, response.getSw());

    // Create a 500-byte NDEF payload with a deterministic pattern
    int payloadLen = 500;
    byte[] payload = new byte[payloadLen];
    for (int i = 0; i < payloadLen; i++) {
      payload[i] = (byte) (i & 0xFF);
    }

    // Build NDEF data: 2-byte big-endian length + payload
    byte[] ndefData = new byte[2 + payloadLen];
    ndefData[0] = (byte) (payloadLen >> 8);
    ndefData[1] = (byte) (payloadLen & 0xFF);
    System.arraycopy(payload, 0, ndefData, 2, payloadLen);

    // Store the NDEF data (SDK handles input segmentation automatically)
    response = cmdSet.setNDEF(payload);
    assertEquals(0x9000, response.getSw());

    // Total stored length = payload (500) + 2-byte length header = 502 bytes
    int totalLen = payloadLen + 2;
    int maxChunk = (SecureChannelV2.SC_MAX_RESPONSE_LENGTH / 4) * 4;

    // Verify individual segment boundaries
    response = cmdSet.getDataRaw(KeycardApplet.STORE_DATA_P1_NDEF, (byte) 0);
    assertEquals(0x9000, response.getSw());
    assertEquals(maxChunk, response.getData().length, "First segment should be max size");

    response = cmdSet.getDataRaw(KeycardApplet.STORE_DATA_P1_NDEF, (byte) (maxChunk / 4));
    assertEquals(0x9000, response.getSw());
    assertEquals(maxChunk, response.getData().length, "Second segment should be max size");

    // Last segment
    int lastOffset = (short) (maxChunk * 2);
    response = cmdSet.getDataRaw(KeycardApplet.STORE_DATA_P1_NDEF, (byte) (lastOffset / 4));
    assertEquals(0x9000, response.getSw());
    assertEquals(totalLen - lastOffset, response.getData().length, "Last segment size mismatch");

    // Offset beyond data fails empty
    response = cmdSet.getDataRaw(KeycardApplet.STORE_DATA_P1_NDEF, (byte) ((totalLen + 3) / 4));
    assertEquals(0x6A86, response.getSw());
  }

  @Test
  @DisplayName("Test the Cash applet (SELECT only)")
  void cashTest() throws Exception {
    CashCommandSet cashCmdSet = new CashCommandSet(sdkChannel);
    APDUResponse response = cashCmdSet.select();
    assertEquals(0x9000, response.getSw());

    CashApplicationInfo info = new CashApplicationInfo(response.getData());
    assertTrue(info.getAppVersion() > 0);
  }

  @Test
  @DisplayName("Mnemonic load and derivation")
  @Tag("manual")
  void mnemonicTest() throws Exception {
    if (cmdSet.getApplicationInfo().hasSecureChannelCapability()) {
      cmdSet.autoOpenSecureChannel();
    }

    APDUResponse response;

    if (cmdSet.getApplicationInfo().hasCredentialsManagementCapability()) {
      response = cmdSet.verifyPIN("000000");
      assertEquals(0x9000, response.getSw());
    }

    byte[] seed = Mnemonic.toBinarySeed("legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal will", "");
    response = cmdSet.loadKey(seed);
    assertEquals(0x9000, response.getSw());

    response = cmdSet.exportKey("m", false, true);
    assertEquals(0x9000, response.getSw());

    BIP32KeyPair pubKey = BIP32KeyPair.fromTLV(response.getData());
    assertEquals("04cc620f846055ed43995391ca5e490c52251ea40453f64a0515bef84c24a653a7c4e02b9de56f66d9ee58dc6b591b534f5a20c0550b2c33a086b90b866cf70799", Hex.toHexString(pubKey.getPublicKey()));

    response = cmdSet.exportKey("m/43'/60'/1581'/0'/0", false, true);
    assertEquals(0x9000, response.getSw());

    pubKey = BIP32KeyPair.fromTLV(response.getData());
    assertEquals("04e7370d118461e1ab01f3e86e88c4b0c7b92cecb79c5e320cef73dda912f173beae74df15090b6405a274963c054cdfe6ac7843a302c260390d1fe776008f310e", Hex.toHexString(pubKey.getPublicKey()));
  }

  @Test
  @DisplayName("Sign actual Ethereum transaction")
  @Tag("manual")
  void signTransactionTest() throws Exception {
    // Initialize credentials
    Web3j web3j = Web3j.build(new HttpService());
    Credentials wallet1 = WalletUtils.loadCredentials("testwallet", "testwallets/wallet1.json");
    Credentials wallet2 = WalletUtils.loadCredentials("testwallet", "testwallets/wallet2.json");

    // Load keys on card
    cmdSet.autoOpenSecureChannel();
    APDUResponse response = cmdSet.verifyPIN("000000");
    assertEquals(0x9000, response.getSw());
    response = cmdSet.loadKey(wallet1.getEcKeyPair());
    assertEquals(0x9000, response.getSw());

    // Verify balance
    System.out.println("Wallet 1 balance: " + web3j.ethGetBalance(wallet1.getAddress(), DefaultBlockParameterName.LATEST).send().getBalance());
    System.out.println("Wallet 2 balance: " + web3j.ethGetBalance(wallet2.getAddress(), DefaultBlockParameterName.LATEST).send().getBalance());

    // Create transaction
    BigInteger gasPrice = web3j.ethGasPrice().send().getGasPrice();
    BigInteger weiValue = Convert.toWei(BigDecimal.valueOf(1.0), Convert.Unit.FINNEY).toBigIntegerExact();
    BigInteger nonce = web3j.ethGetTransactionCount(wallet1.getAddress(), DefaultBlockParameterName.LATEST).send().getTransactionCount();

    RawTransaction rawTransaction = RawTransaction.createEtherTransaction(nonce, gasPrice, Transfer.GAS_LIMIT, wallet2.getAddress(), weiValue);

    // Sign transaction
    byte[] txBytes = TransactionEncoder.encode(rawTransaction);
    Sign.SignatureData signature = signMessage(txBytes);

    Method encode = TransactionEncoder.class.getDeclaredMethod("encode", RawTransaction.class, Sign.SignatureData.class);
    encode.setAccessible(true);

    // Send transaction
    byte[] signedMessage = (byte[]) encode.invoke(null, rawTransaction, signature);
    String hexValue = "0x" + Hex.toHexString(signedMessage);
    EthSendTransaction ethSendTransaction = web3j.ethSendRawTransaction(hexValue).send();

    if (ethSendTransaction.hasError()) {
      System.out.println("Transaction Error: " + ethSendTransaction.getError().getMessage());
    }

    assertFalse(ethSendTransaction.hasError());
  }


  private KeyPairGenerator keypairGenerator() throws Exception {
    ECParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec("secp256k1");
    KeyPairGenerator g = KeyPairGenerator.getInstance("ECDH", "BC");
    g.initialize(ecSpec);

    return g;
  }

  private byte[] extractSignature(byte[] sig) {
    int off = sig[4] + 5;
    return Arrays.copyOfRange(sig, off, off + sig[off + 1] + 2);
  }

  private byte[] extractPublicKeyFromSignature(byte[] sig) {
    assertEquals(KeycardApplet.TLV_SIGNATURE_TEMPLATE, sig[0]);
    assertEquals((byte) 0x81, sig[1]);
    assertEquals(KeycardApplet.TLV_PUB_KEY, sig[3]);

    return Arrays.copyOfRange(sig, 5, 5 + sig[4]);
  }

  private void reset() {
    switch(TARGET) {
      case TARGET_SIMULATOR:
        simulator.reset();
        break;
      case TARGET_CARD:
        apduChannel.getCard().getATR();
        break;
      default:
        break;
    }
  }

  private void resetAndSelectAndOpenSC() throws Exception {
    if (cmdSet.getApplicationInfo().hasSecureChannelCapability()) {
      reset();
      cmdSet.select();
      cmdSet.autoOpenSecureChannel();
    }
  }

  private void assertMnemonic(int expectedLength, byte[] data) {
    short[] shorts = new short[data.length / 2];
    assertEquals(expectedLength, shorts.length);
    ByteBuffer.wrap(data).order(ByteOrder.BIG_ENDIAN).asShortBuffer().get(shorts);

    boolean[] bits = new boolean[11 * shorts.length];
    int i = 0;

    for (short mIdx : shorts) {
      assertTrue(mIdx >= 0 && mIdx < 2048);
      for (int j = 0; j < 11; ++j) {
        bits[i++] = (mIdx & (1 << (10 - j))) > 0;
      }
    }

    data = new byte[bits.length / 33 * 4];

    for (i = 0; i < bits.length / 33 * 32; ++i) {
      data[i / 8] |= (bits[i] ? 1 : 0) << (7 - (i % 8));
    }

    byte[] check = sha256(data);

    for (i = bits.length / 33 * 32; i < bits.length; ++i) {
      if ((check[(i - bits.length / 33 * 32) / 8] & (1 << (7 - (i % 8))) ^ (bits[i] ? 1 : 0) << (7 - (i % 8))) != 0) {
        fail("Checksum is invalid");
      }
    }
  }

  private void verifyExportedKey(byte[] keyTemplate, KeyPair keyPair, byte[] chainCode, int[] path, boolean publicOnly, boolean extendedPublic) {
    if (!cmdSet.getApplicationInfo().hasKeyManagementCapability()) {
      return;
    }

    DeterministicKey dk = deriveKey(keyPair, chainCode, path);
    ECKey key = dk.decompress();
    assertEquals(KeycardApplet.TLV_KEY_TEMPLATE, keyTemplate[0]);
    
    if (publicOnly) {
      assertEquals(KeycardApplet.TLV_PUB_KEY, keyTemplate[2]);
      byte[] pubKey = Arrays.copyOfRange(keyTemplate, 4, 4 + keyTemplate[3]);
      
      assertArrayEquals(key.getPubKey(), pubKey);
      int templateLen = 2 + pubKey.length;

      if (extendedPublic) {
        byte[] chain = Arrays.copyOfRange(keyTemplate, templateLen + 4, templateLen + 4 + keyTemplate[3 + templateLen]);
        assertEquals(KeycardApplet.TLV_CHAIN_CODE, keyTemplate[2 + templateLen]);        
        assertArrayEquals(dk.getChainCode(), chain);
        templateLen += 2 + chain.length;
      }      

      assertEquals(templateLen, keyTemplate[1]);
      assertEquals(templateLen + 2, keyTemplate.length);
    } else {
      assertEquals(KeycardApplet.TLV_PRIV_KEY, keyTemplate[2]);
      byte[] privateKey = Arrays.copyOfRange(keyTemplate, 4, 4 + keyTemplate[3]);

      byte[] tPrivKey = key.getPrivKey().toByteArray();

      if (tPrivKey[0] == 0x00) {
        tPrivKey = Arrays.copyOfRange(tPrivKey, 1, tPrivKey.length);
      }

      assertArrayEquals(tPrivKey, privateKey);
    }
  }

  private DeterministicKey deriveKey(KeyPair keyPair, byte[] chainCode, int[] path) {
    DeterministicKey key = HDKeyDerivation.createMasterPrivKeyFromBytes(((org.bouncycastle.jce.interfaces.ECPrivateKey) keyPair.getPrivate()).getD().toByteArray(), chainCode);

    for (int i : path) {
      key = HDKeyDerivation.deriveChildKey(key, new ChildNumber(i));
    }

    return key;
  }

  private boolean isMalleable(byte[] sig) {
    int rLen = sig[3];
    int sOff = 6 + rLen;
    int sLen = sig.length - rLen - 6;

    BigInteger s = new BigInteger(Arrays.copyOfRange(sig, sOff, sOff + sLen));
    BigInteger limit = new BigInteger("7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0", 16);

    return s.compareTo(limit) >= 1;
  }

  /**
   * Signs a signature using the card. Returns a SignatureData object which contains v, r and s. The algorithm to do
   * this is as follow:
   *
   * 1) The Keccak-256 hash of transaction is generated off-card
   * 2) A SIGN command is sent to the card to sign the precomputed hash
   * 3) The returned data is the public key and the signature
   * 4) The signature and public key can be used to generate the v value. The v value allows to recover the public key
   *    from the signature. Here we use the web3j implementation through reflection
   * 5) v, r and s are the final signature to append to the transaction
   *
   * @param message the raw transaction
   * @return the signature data
   */
  private Sign.SignatureData signMessage(byte[] message) throws Exception {
    byte[] messageHash = Hash.sha3(message);

    APDUResponse response = cmdSet.signWithPath(messageHash, "m", false);
    assertEquals(0x9000, response.getSw());
    byte[] respData = response.getData();
    byte[] rawSig = extractSignature(respData);

    int rLen = rawSig[3];
    int sOff = 6 + rLen;
    int sLen = rawSig.length - rLen - 6;

    BigInteger r = new BigInteger(Arrays.copyOfRange(rawSig, 4, 4 + rLen));
    BigInteger s = new BigInteger(Arrays.copyOfRange(rawSig, sOff, sOff + sLen));

    Class<?> ecdsaSignature = Class.forName("org.web3j.crypto.Sign$ECDSASignature");
    Constructor<?> ecdsaSignatureConstructor = ecdsaSignature.getDeclaredConstructor(BigInteger.class, BigInteger.class);
    ecdsaSignatureConstructor.setAccessible(true);
    Object sig = ecdsaSignatureConstructor.newInstance(r, s);
    Method m = ecdsaSignature.getMethod("toCanonicalised");
    m.setAccessible(true);
    sig = m.invoke(sig);

    Method recoverFromSignature = Sign.class.getDeclaredMethod("recoverFromSignature", int.class, ecdsaSignature, byte[].class);
    recoverFromSignature.setAccessible(true);

    byte[] pubData = extractPublicKeyFromSignature(respData);
    BigInteger publicKey = new BigInteger(Arrays.copyOfRange(pubData, 1, pubData.length));

    int recId = -1;
    for (int i = 0; i < 4; i++) {
      BigInteger k = (BigInteger) recoverFromSignature.invoke(null, i, sig, messageHash);
      if (k != null && k.equals(publicKey)) {
        recId = i;
        break;
      }
    }
    if (recId == -1) {
      throw new RuntimeException("Could not construct a recoverable key. This should never happen.");
    }

    int headerByte = recId + 27;

    Field rF = ecdsaSignature.getDeclaredField("r");
    rF.setAccessible(true);
    Field sF = ecdsaSignature.getDeclaredField("s");
    sF.setAccessible(true);
    r = (BigInteger) rF.get(sig);
    s = (BigInteger) sF.get(sig);

    // 1 header + 32 bytes for R + 32 bytes for S
    byte v = (byte) headerByte;
    byte[] rB = Numeric.toBytesPadded(r, 32);
    byte[] sB = Numeric.toBytesPadded(s, 32);

    return new Sign.SignatureData(v, rB, sB);
  }

  private void verifyKeyUID(byte[] keyUID, ECPublicKey pubKey) {
    verifyKeyUID(keyUID, pubKey.getQ().getEncoded(false));
  }

  private void verifyKeyUID(byte[] keyUID, byte[] pubKey) {
    assertArrayEquals(sha256(pubKey), keyUID);
  }
}
