package im.status.keycard;

import im.status.keycard.applet.Certificate;

import java.security.KeyPair;

/**
 * Identity certificates for test and simulator personalization.
 */
public class TestIdentity {
  /**
   * The Ident applet's STORE DATA payload: certificate || 32-byte identity private key. The SDK serializes the key
   * without left-padding, so about 1 in 100 random identities (a leading zero byte) comes out one byte short and the
   * applet rejects it with 6A80. Generate until the length is right.
   */
  public static byte[] certStoreData(KeyPair caKeyPair) throws Exception {
    while (true) {
      byte[] data = Certificate.createCertificate(caKeyPair, Certificate.generateIdentKeyPair()).toStoreData();
      if (data.length == SharedMemory.CERT_LEN + Crypto.KEY_SECRET_SIZE) {
        return data;
      }
    }
  }
}
