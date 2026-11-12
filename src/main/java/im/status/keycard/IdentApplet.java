package im.status.keycard;

import javacard.framework.*;
import javacard.security.*;

/**
 * The applet's main class. All incoming commands a processed by this class.
 */
public class IdentApplet extends Applet {
  static final byte TLV_CERT = (byte) 0x8A;

  // identity states, kept in SharedMemory.idCert[0] (docs/ON_CARD_IDENTITY.md)
  static final byte ID_EMPTY = (byte) 0x00;
  static final byte ID_GENERATED = (byte) 0x55;
  static final byte CERT_VALID = (byte) 0xAA;

  static final short ID_PUB_LEN = 33;

  static final byte INS_IDENTIFY_CARD = (byte) 0x14;
  static final byte INS_GENERATE_IDENTITY = (byte) 0x16;

  /**
   * Invoked during applet installation. Creates an instance of this class. The installation parameters are passed in
   * the given buffer.
   *
   * @param bArray installation parameters buffer
   * @param bOffset offset where the installation parameters begin
   * @param bLength length of the installation parameters
   */
  public static void install(byte[] bArray, short bOffset, byte bLength) {
    new IdentApplet(bArray, bOffset, bLength);
  }

  /**
   * Application constructor. All memory allocation is done here. The reason for this is two-fold: first the card might
   * not have Garbage Collection so dynamic allocation will eventually eat all memory. The second reason is to be sure
   * that if the application installs successfully, there is no risk of running out of memory because of other applets
   * allocating memory. The constructor also registers the applet with the JCRE so that it becomes selectable.
   *
   * @param bArray installation parameters buffer
   * @param bOffset offset where the installation parameters begin
   * @param bLength length of the installation parameters
   */
  public IdentApplet(byte[] bArray, short bOffset, byte bLength) {
    SharedMemory.idPrivate = (ECPrivateKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PRIVATE, SECP256k1.SECP256K1_KEY_SIZE, false);
    ECPublicKey idPublic = (ECPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PUBLIC, SECP256k1.SECP256K1_KEY_SIZE, false);
    SECP256k1.setCurveParameters(SharedMemory.idPrivate);
    SECP256k1.setCurveParameters(idPublic);
    SharedMemory.idKeyPair = new KeyPair(idPublic, SharedMemory.idPrivate);
    SharedMemory.idCert[0] = ID_EMPTY;
    register(bArray, (short) (bOffset + 1), bArray[bOffset]);
  }

  /**
   * This method is called on every incoming APDU. This method is just a dispatcher which invokes the correct method
   * depending on the INS of the APDU.
   *
   * @param apdu the JCRE-owned APDU object.
   * @throws ISOException any processing error
   */
  public void process(APDU apdu) throws ISOException {
    if (selectingApplet()) {
      processSelect(apdu);
      return;
    }

    byte[] apduBuffer = apdu.getBuffer();

    switch (apduBuffer[ISO7816.OFFSET_INS]) {
      case INS_GENERATE_IDENTITY:
        processGenerateIdentity(apdu);
        break;
      case KeycardApplet.INS_STORE_DATA:
        processStoreData(apdu);
        break;
      default:
        ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        break;
    }
  }

  private void processSelect(APDU apdu) {
    byte[] apduBuffer = apdu.getBuffer();
    apdu.setIncomingAndReceive();

    // certified: the certificate; generated: just the public key, so a host can resume after a drop without
    // generating (and getting signed) a second key
    short len = 0;
    if (SharedMemory.idCert[0] == CERT_VALID) {
      len = SharedMemory.CERT_LEN;
    } else if (SharedMemory.idCert[0] == ID_GENERATED) {
      len = ID_PUB_LEN;
    }

    if (len > 0) {
      Util.arrayCopyNonAtomic(SharedMemory.idCert, (short) 1, apduBuffer, (short) 0, len);
      apdu.setOutgoingAndSend((short) 0, len);
    }
  }

  /**
   * Generates the identity key pair on card and returns the compressed public key. Allowed until the card is
   * certified; generating again replaces the key, so a certificate for the old one no longer matches.
   */
  private void processGenerateIdentity(APDU apdu) {
    if (SharedMemory.idCert[0] == CERT_VALID) {
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }

    byte[] apduBuffer = apdu.getBuffer();

    // cleared first, so a tear during generation leaves EMPTY rather than GENERATED with a stale public key
    SharedMemory.idCert[0] = ID_EMPTY;
    SharedMemory.idKeyPair.genKeyPair();

    // 04 X Y -> 02/03 X
    ((ECPublicKey) SharedMemory.idKeyPair.getPublic()).getW(apduBuffer, (short) 0);
    apduBuffer[0] = (byte) (0x02 | (apduBuffer[64] & 0x01));

    JCSystem.beginTransaction();
    Util.arrayCopy(apduBuffer, (short) 0, SharedMemory.idCert, (short) 1, ID_PUB_LEN);
    SharedMemory.idCert[0] = ID_GENERATED;
    JCSystem.commitTransaction();

    apdu.setOutgoingAndSend((short) 0, ID_PUB_LEN);
  }

  /**
   * Stores the CA certificate for the generated key. The certificate is write-once and must name the key this card
   * generated; the private key never leaves the card.
   */
  private void processStoreData(APDU apdu) {
    if (SharedMemory.idCert[0] != ID_GENERATED) {
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }

    byte[] apduBuffer = apdu.getBuffer();
    apdu.setIncomingAndReceive();

    if (Util.makeShort((byte) 0, apduBuffer[ISO7816.OFFSET_LC]) != SharedMemory.CERT_LEN) {
      ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    }

    if (Util.arrayCompare(apduBuffer, ISO7816.OFFSET_CDATA, SharedMemory.idCert, (short) 1, ID_PUB_LEN) != 0) {
      ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    }

    JCSystem.beginTransaction();
    Util.arrayCopy(apduBuffer, (short) (ISO7816.OFFSET_CDATA + ID_PUB_LEN), SharedMemory.idCert, (short) (1 + ID_PUB_LEN), (short) (SharedMemory.CERT_LEN - ID_PUB_LEN));
    SharedMemory.idCert[0] = CERT_VALID;
    JCSystem.commitTransaction();
  }
}
