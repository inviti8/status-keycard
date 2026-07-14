package im.status.keycard;

import com.licel.jcardsim.smartcardio.CardSimulator;
import com.licel.jcardsim.utils.AIDUtil;
import javacard.framework.Applet;
import javacard.framework.APDU;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.Util;
import javacard.security.ECPrivateKey;
import javacard.security.KeyAgreement;
import javacard.security.KeyBuilder;
import javacard.security.RSAPublicKey;
import javacardx.crypto.Cipher;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import java.math.BigInteger;
import java.security.SecureRandom;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * M2 feasibility probe (temporary): verifies that the crypto primitives needed for on-card
 * Ed25519 (Core C, Wei25519 approach) work in the simulator:
 *
 *   1. BigNumberMath.modMul with an arbitrary modulus (Ed25519 group order L) — RSA e=2 trick
 *   2. Native EC scalar multiplication (ALG_EC_SVDP_DH_PLAIN_XY) on the custom Wei25519 curve
 *   3. Modular inversion mod p = 2^255-19 via RSA modPow with exponent p-2 (JCMathLib mechanism)
 *   4. BigNumberMath.modRed reducing a 64-byte (SHA-512-sized) value mod L
 *
 * Host side cross-checks everything with BigInteger / BouncyCastle.
 */
public class Ed25519ProbeTest {
  // Wei25519: short-Weierstrass form of Ed25519/Curve25519 (constants from JCMathLib, MIT).
  // Built with repeat() to avoid hand-count typos; verified against the curve equation in setup().
  static final String P_HEX = "7f" + repeat("ff", 30) + "ed";
  static final String A_HEX = "2a" + repeat("aa", 26) + "984914a144";
  static final String B_HEX = "7b425ed097b425ed097b425ed097b425ed097b425ed097b4260b5e9c7710c864";
  static final String GX_HEX = "2a" + repeat("aa", 28) + "ad245a";
  static final String GY_HEX = "20ae19a1b8a086b4e01edd2c7748d14c923d4d7e6d7c61b229e9c5a27eced3d9";
  static final String L_HEX = "1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed";

  static String repeat(String s, int n) {
    StringBuilder sb = new StringBuilder();
    for (int i = 0; i < n; i++) {
      sb.append(s);
    }
    return sb.toString();
  }

  static final BigInteger P = new BigInteger(P_HEX, 16);
  static final BigInteger A = new BigInteger(A_HEX, 16);
  static final BigInteger B = new BigInteger(B_HEX, 16);
  static final BigInteger GX = new BigInteger(GX_HEX, 16);
  static final BigInteger GY = new BigInteger(GY_HEX, 16);
  static final BigInteger L = new BigInteger(L_HEX, 16);

  static final byte INS_SETUP = 0x00;
  static final byte INS_MODMUL = 0x01;
  static final byte INS_SCALARMULT = 0x02;
  static final byte INS_MODINV = 0x03;
  static final byte INS_MODRED = 0x04;

  public static class ProbeApplet extends Applet {
    Crypto crypto;
    KeyAgreement ka;
    ECPrivateKey wei;
    RSAPublicKey invKey;
    Cipher invCiph;
    byte[] g;      // 65-byte Wei25519 base point
    byte[] order;  // 32-byte L
    byte[] tmp;

    public static void install(byte[] bArray, short bOffset, byte bLength) {
      new ProbeApplet().register();
    }

    ProbeApplet() {
      crypto = new Crypto();
      ka = KeyAgreement.getInstance((byte) 6 /* ALG_EC_SVDP_DH_PLAIN_XY */, false);
      wei = (ECPrivateKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PRIVATE, (short) 256, false);
      invKey = (RSAPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PUBLIC, (short) 256, false);
      invCiph = Cipher.getInstance(Cipher.ALG_RSA_NOPAD, false);
      g = new byte[65];
      order = new byte[32];
      tmp = new byte[96];
    }

    public void process(APDU apdu) {
      if (selectingApplet()) {
        return;
      }

      apdu.setIncomingAndReceive();
      byte[] buf = apdu.getBuffer();
      short cdata = ISO7816.OFFSET_CDATA;

      switch (buf[ISO7816.OFFSET_INS]) {
        case INS_SETUP:
          // data: P(32) A(32) B(32) G(65) L(32) PM2(32) = 225 bytes
          wei.setFieldFP(buf, cdata, (short) 32);
          wei.setA(buf, (short) (cdata + 32), (short) 32);
          wei.setB(buf, (short) (cdata + 64), (short) 32);
          wei.setG(buf, (short) (cdata + 96), (short) 65);
          wei.setR(buf, (short) (cdata + 161), (short) 32);
          wei.setK((short) 8);
          Util.arrayCopyNonAtomic(buf, (short) (cdata + 96), g, (short) 0, (short) 65);
          Util.arrayCopyNonAtomic(buf, (short) (cdata + 161), order, (short) 0, (short) 32);
          invKey.setModulus(buf, cdata, (short) 32);
          invKey.setExponent(buf, (short) (cdata + 193), (short) 32);
          apdu.setOutgoingAndSend((short) 0, (short) 0);
          break;
        case INS_MODMUL:
          // data: a(32) b(32); result = a*b mod L
          crypto.bigMath.modMul(buf, cdata, (short) 32, buf, (short) (cdata + 32), (short) 32, order, (short) 0, (short) 32);
          apdu.setOutgoingAndSend(cdata, (short) 32);
          break;
        case INS_SCALARMULT:
          // data: k(32); result = 04 || X(32) || Y(32) on Wei25519
          wei.setS(buf, cdata, (short) 32);
          ka.init(wei);
          short outLen = ka.generateSecret(g, (short) 0, (short) 65, tmp, (short) 0);
          Util.arrayCopyNonAtomic(tmp, (short) 0, buf, (short) 0, outLen);
          apdu.setOutgoingAndSend((short) 0, outLen);
          break;
        case INS_MODINV:
          // data: x(32); result = x^(p-2) mod p
          invCiph.init(invKey, Cipher.MODE_DECRYPT);
          short len = invCiph.doFinal(buf, cdata, (short) 32, tmp, (short) 0);
          if (len < 32) {
            // simulator may strip leading zeroes
            Util.arrayCopyNonAtomic(tmp, (short) 0, tmp, (short) (32 - len), len);
            Util.arrayFillNonAtomic(tmp, (short) 0, (short) (32 - len), (byte) 0);
          }
          Util.arrayCopyNonAtomic(tmp, (short) 0, buf, (short) 0, (short) 32);
          apdu.setOutgoingAndSend((short) 0, (short) 32);
          break;
        case INS_MODRED:
          // data: x(64); result = x mod L (returned as full 64-byte buffer)
          crypto.bigMath.modRed(buf, cdata, (short) 64, order, (short) 0, (short) 32);
          apdu.setOutgoingAndSend(cdata, (short) 64);
          break;
        default:
          ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
      }
    }
  }

  static CardSimulator sim;

  @BeforeAll
  static void setup() {
    // sanity: G must satisfy y^2 = x^3 + ax + b mod p
    assertEquals(GY.multiply(GY).mod(P), GX.pow(3).add(A.multiply(GX)).add(B).mod(P), "Wei25519 G on curve");

    sim = new CardSimulator();
    sim.installApplet(AIDUtil.create("A000000000"), ProbeApplet.class);
    sim.selectApplet(AIDUtil.create("A000000000"));

    byte[] setupData = new byte[225];
    System.arraycopy(to32(P), 0, setupData, 0, 32);
    System.arraycopy(to32(A), 0, setupData, 32, 32);
    System.arraycopy(to32(B), 0, setupData, 64, 32);
    setupData[96] = 0x04;
    System.arraycopy(to32(GX), 0, setupData, 97, 32);
    System.arraycopy(to32(GY), 0, setupData, 129, 32);
    System.arraycopy(to32(L), 0, setupData, 161, 32);
    System.arraycopy(to32(P.subtract(BigInteger.valueOf(2))), 0, setupData, 193, 32);

    ResponseAPDU resp = sim.transmitCommand(new CommandAPDU(0x00, INS_SETUP, 0, 0, setupData));
    assertEquals(0x9000, resp.getSW(), "curve/RSA setup must succeed");
  }

  static byte[] to32(BigInteger v) {
    byte[] raw = v.toByteArray();
    byte[] out = new byte[32];
    if (raw.length >= 32) {
      System.arraycopy(raw, raw.length - 32, out, 0, 32);
    } else {
      System.arraycopy(raw, 0, out, 32 - raw.length, raw.length);
    }
    return out;
  }

  static byte[] send(byte ins, byte[] data, int expectedLen) {
    ResponseAPDU resp = sim.transmitCommand(new CommandAPDU(0x00, ins, 0, 0, data));
    assertEquals(0x9000, resp.getSW(), "INS " + ins + " must succeed");
    assertEquals(expectedLen, resp.getData().length, "INS " + ins + " response length");
    return resp.getData();
  }

  @Test
  @DisplayName("1. bigMath.modMul mod L (RSA e=2 squaring trick)")
  void modMul() {
    SecureRandom rnd = new SecureRandom();
    for (int i = 0; i < 5; i++) {
      BigInteger a = new BigInteger(255, rnd).mod(L);
      BigInteger b = new BigInteger(255, rnd).mod(L);
      byte[] data = new byte[64];
      System.arraycopy(to32(a), 0, data, 0, 32);
      System.arraycopy(to32(b), 0, data, 32, 32);
      byte[] out = send(INS_MODMUL, data, 32);
      assertArrayEquals(to32(a.multiply(b).mod(L)), out, "a*b mod L, iteration " + i);
    }
  }

  @Test
  @DisplayName("2. native XY scalar multiplication on Wei25519")
  void scalarMult() {
    ECCurve curve = new ECCurve.Fp(P, A, B);
    ECPoint gPoint = curve.createPoint(GX, GY);

    SecureRandom rnd = new SecureRandom();
    for (int i = 0; i < 3; i++) {
      BigInteger k = new BigInteger(250, rnd).mod(L).add(BigInteger.ONE);
      byte[] out = send(INS_SCALARMULT, to32(k), 65);
      byte[] expected = gPoint.multiply(k).normalize().getEncoded(false);
      assertArrayEquals(expected, out, "k*G on Wei25519, iteration " + i);
    }
  }

  @Test
  @DisplayName("3. modular inversion mod p via RSA modPow(p-2)")
  void modInv() {
    SecureRandom rnd = new SecureRandom();
    for (int i = 0; i < 8; i++) {
      BigInteger x = new BigInteger(254, rnd).mod(P);
      if (x.signum() == 0) {
        continue;
      }
      byte[] out = send(INS_MODINV, to32(x), 32);
      assertArrayEquals(to32(x.modInverse(P)), out, "x^-1 mod p, iteration " + i);
      // round trip: x * inv(x) == 1 mod p
      assertEquals(BigInteger.ONE, x.multiply(new BigInteger(1, out)).mod(P), "x * inv(x) mod p, iteration " + i);
    }
  }

  /**
   * Regression tests guarding the RSA inversion trick (modulus p, exponent p-2, single
   * ALG_RSA_NOPAD operation). These are the cases most likely to break on a different
   * RSA implementation (real card or simulator change): identity values, the largest
   * input, and results with leading zero bytes (shorter-than-block cipher outputs).
   */
  @Test
  @DisplayName("3b. inversion trick edge cases")
  void modInvEdgeCases() {
    // 1^-1 = 1
    assertArrayEquals(to32(BigInteger.ONE), send(INS_MODINV, to32(BigInteger.ONE), 32), "inv(1)");

    // 2^-1 = (p+1)/2
    BigInteger two = BigInteger.valueOf(2);
    assertArrayEquals(to32(P.add(BigInteger.ONE).shiftRight(1)), send(INS_MODINV, to32(two), 32), "inv(2)");

    // (p-1)^-1 = p-1 (its own inverse)
    BigInteger pm1 = P.subtract(BigInteger.ONE);
    assertArrayEquals(to32(pm1), send(INS_MODINV, to32(pm1), 32), "inv(p-1)");

    // results with 1..3 leading zero BYTES: request inv(y^-1) so the card must output y
    // exactly, zero-padded to 32 bytes (exercises short cipher output handling)
    SecureRandom rnd = new SecureRandom();
    for (int zeroBytes = 1; zeroBytes <= 3; zeroBytes++) {
      BigInteger y = new BigInteger(8 * (32 - zeroBytes) - 1, rnd);
      BigInteger x = y.modInverse(P);
      byte[] out = send(INS_MODINV, to32(x), 32);
      assertArrayEquals(to32(y), out, "inv with " + zeroBytes + " leading zero bytes");
    }
  }

  @Test
  @DisplayName("4. bigMath.modRed 64-byte value mod L")
  void modRed64() {
    SecureRandom rnd = new SecureRandom();
    byte[] data = new byte[64];
    rnd.nextBytes(data);
    BigInteger x = new BigInteger(1, data);

    byte[] out = send(INS_MODRED, data, 64);
    byte[] expectedTail = to32(x.mod(L));
    byte[] actualTail = new byte[32];
    System.arraycopy(out, 32, actualTail, 0, 32);
    assertArrayEquals(expectedTail, actualTail, "x mod L (low 32 bytes of in-place result)");
  }
}
