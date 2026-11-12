package im.status.keycard;

import im.status.keycard.applet.IdentCommandSet;
import im.status.keycard.io.APDUCommand;
import im.status.keycard.io.APDUResponse;
import im.status.keycard.io.CardChannel;
import org.bouncycastle.asn1.sec.SECNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.signers.ECDSASigner;
import org.bouncycastle.crypto.signers.HMacDSAKCalculator;
import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.util.Arrays;

/**
 * Identity personalization for tests and the simulator: the card generates its identity key, the CA signs the
 * public key here, and only the certificate goes back (docs/ON_CARD_IDENTITY.md).
 */
public class TestIdentity {
  static final X9ECParameters CURVE_PARAMS = SECNamedCurves.getByName("secp256k1");
  static final ECDomainParameters CURVE = new ECDomainParameters(CURVE_PARAMS.getCurve(), CURVE_PARAMS.getG(), CURVE_PARAMS.getN(), CURVE_PARAMS.getH());

  static final int GENERATE_IDENTITY = 0x16;

  /**
   * Personalizes the identity if needed and returns the certificate. Idempotent: a certified card is left as it is
   * (the certificate is write-once), and a generated but uncertified one is certified without generating again.
   */
  public static byte[] provision(CardChannel channel, KeyPair caKeyPair) throws Exception {
    IdentCommandSet idCmdSet = new IdentCommandSet(channel);
    byte[] data = idCmdSet.select().checkOK().getData();

    if (data.length == SharedMemory.CERT_LEN) {
      return data;
    }

    byte[] pub = (data.length == IdentApplet.ID_PUB_LEN) ? data : generate(channel);
    byte[] cert = certify(caKeyPair, pub);
    idCmdSet.storeData(cert).checkOK();
    return cert;
  }

  /** Sends GENERATE IDENTITY to the selected Ident applet and returns the compressed public key. */
  public static byte[] generate(CardChannel channel) throws Exception {
    long start = System.nanoTime();
    APDUResponse resp = channel.send(new APDUCommand(0x80, GENERATE_IDENTITY, 0, 0, new byte[0], true)).checkOK();
    System.out.println("[ident] GENERATE IDENTITY: " + ((System.nanoTime() - start) / 1000000) + " ms");
    return resp.getData();
  }

  /**
   * The 98-byte certificate for an identity public key: pub || r || s || v, signed over SHA-256(pub). The signature
   * is normalised to low S and v is computed for the normalised pair, as the production host must do.
   */
  public static byte[] certify(KeyPair caKeyPair, byte[] pub) throws Exception {
    byte[] hash = MessageDigest.getInstance("SHA-256").digest(pub);
    BigInteger d = ((org.bouncycastle.jce.interfaces.ECPrivateKey) caKeyPair.getPrivate()).getD();
    byte[] caPub = ((org.bouncycastle.jce.interfaces.ECPublicKey) caKeyPair.getPublic()).getQ().getEncoded(true);

    ECDSASigner signer = new ECDSASigner(new HMacDSAKCalculator(new SHA256Digest()));
    signer.init(true, new ECPrivateKeyParameters(d, CURVE));
    BigInteger[] rs = signer.generateSignature(hash);
    BigInteger r = rs[0];
    BigInteger s = rs[1];

    if (s.compareTo(CURVE.getN().shiftRight(1)) > 0) {
      s = CURVE.getN().subtract(s);
    }

    int v = -1;
    for (int i = 0; i < 2; i++) {
      ECPoint q = recover(i, hash, r, s);
      if (q != null && Arrays.equals(q.getEncoded(true), caPub)) {
        v = i;
        break;
      }
    }

    if (v < 0) {
      throw new IllegalStateException("no recovery id reproduces the CA key");
    }

    byte[] cert = new byte[SharedMemory.CERT_LEN];
    System.arraycopy(pub, 0, cert, 0, IdentApplet.ID_PUB_LEN);
    System.arraycopy(toBytes32(r), 0, cert, 33, 32);
    System.arraycopy(toBytes32(s), 0, cert, 65, 32);
    cert[97] = (byte) v;
    return cert;
  }

  /** Recovers the signer's public key for recovery id 0 or 1 (R.x = r), or null if R is not on the curve. */
  static ECPoint recover(int recId, byte[] hash, BigInteger r, BigInteger s) {
    byte[] rEnc = new byte[33];
    rEnc[0] = (byte) (0x02 | recId);
    System.arraycopy(toBytes32(r), 0, rEnc, 1, 32);

    ECPoint bigR;
    try {
      bigR = CURVE.getCurve().decodePoint(rEnc);
    } catch (IllegalArgumentException e) {
      return null;
    }

    BigInteger n = CURVE.getN();
    BigInteger e = new BigInteger(1, hash);
    BigInteger rInv = r.modInverse(n);
    return bigR.multiply(s).subtract(CURVE.getG().multiply(e)).multiply(rInv).normalize();
  }

  static byte[] toBytes32(BigInteger x) {
    byte[] b = x.toByteArray();
    byte[] out = new byte[32];
    if (b.length > 32) {
      System.arraycopy(b, b.length - 32, out, 0, 32);
    } else {
      System.arraycopy(b, 0, out, 32 - b.length, b.length);
    }
    return out;
  }
}
