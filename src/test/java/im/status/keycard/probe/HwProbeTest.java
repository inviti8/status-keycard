package im.status.keycard.probe;

import com.licel.jcardsim.smartcardio.CardSimulator;
import com.licel.jcardsim.utils.AIDUtil;
import javacard.framework.AID;
import javacard.framework.ISO7816;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.ec.CustomNamedCurves;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import java.math.BigInteger;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * Runs the hardware probe applet (probe/src) in jcardsim. Every probe must PASS here: that proves
 * the embedded expected values and the result-record format, so a WRONG_RESULT or EXCEPTION
 * reported from a real card is about the card, not the probe. Expected values are recomputed
 * independently with BigInteger / BouncyCastle.
 */
public class HwProbeTest {
  static final AID PROBE_AID = AIDUtil.create("F04B4350524F424501");

  static CardSimulator sim;

  @BeforeAll
  static void setUp() {
    sim = new CardSimulator();
    sim.installApplet(PROBE_AID, HwProbeApplet.class);
    sim.selectApplet(PROBE_AID);
  }

  static byte[] run(int ins, int p1) {
    ResponseAPDU resp = sim.transmitCommand(new CommandAPDU(0x00, ins, p1, 0, 256));
    assertEquals(0x9000, resp.getSW());
    return resp.getData();
  }

  static byte[] assertPass(byte[] record) {
    assertEquals(HwProbeApplet.STATUS_PASS, record[0], "status");
    assertEquals(HwProbeApplet.STAGE_COMPUTE, record[1], "stage");
    assertEquals(HwProbeApplet.EXC_NONE, record[2], "excType");
    assertEquals(0, record[3] | record[4], "reason");
    assertEquals(record.length - HwProbeApplet.HEADER_LEN, record[5] & 0xff, "outLen");
    return Arrays.copyOfRange(record, HwProbeApplet.HEADER_LEN, record.length);
  }

  static byte[] fixed(BigInteger v, int len) {
    byte[] raw = v.toByteArray();
    byte[] out = new byte[len];
    int n = Math.min(raw.length, len);
    System.arraycopy(raw, raw.length - n, out, len - n, n);
    return out;
  }

  static BigInteger scalar() {
    return new BigInteger(1, HwProbeApplet.SCALAR);
  }

  @Test
  @DisplayName("INFO reports the JC version and probe version")
  void info() {
    ResponseAPDU resp = sim.transmitCommand(new CommandAPDU(0x00, HwProbeApplet.INS_INFO, 0, 0, 256));
    assertEquals(0x9000, resp.getSW());
    assertEquals(3, resp.getData().length);
    assertEquals(HwProbeApplet.PROBE_VERSION, resp.getData()[2]);
  }

  @Test
  @DisplayName("256-bit RSA NOPAD computes 2^(p-2) mod p = 2^-1 mod p")
  void rsa256() {
    BigInteger p = new BigInteger(1, HwProbeApplet.WEI_P);
    BigInteger expected = BigInteger.valueOf(2).modPow(p.subtract(BigInteger.valueOf(2)), p);
    assertEquals(BigInteger.ONE, expected.shiftLeft(1).mod(p));
    assertArrayEquals(fixed(expected, 32), assertPass(run(HwProbeApplet.INS_RSA_256, 0)));
  }

  @Test
  @DisplayName("512-bit RSA NOPAD control computes 2^3 = 8")
  void rsa512() {
    assertArrayEquals(fixed(BigInteger.valueOf(8), 64), assertPass(run(HwProbeApplet.INS_RSA_512, 0)));
  }

  @Test
  @DisplayName("Wei25519 scalar multiplication matches BouncyCastle, all three key variants")
  void wei25519() {
    BigInteger p = new BigInteger(1, HwProbeApplet.WEI_P);
    BigInteger l = new BigInteger(1, HwProbeApplet.ED_L);
    ECCurve curve = new ECCurve.Fp(p, new BigInteger(1, HwProbeApplet.WEI_A), new BigInteger(1, HwProbeApplet.WEI_B), l, BigInteger.valueOf(8));
    ECPoint g = curve.decodePoint(HwProbeApplet.WEI_G);
    assertEquals(true, g.multiply(l).isInfinity());
    byte[] expected = g.multiply(scalar()).normalize().getEncoded(false);
    assertArrayEquals(expected, HwProbeApplet.WEI_EXPECTED);

    for (byte variant : new byte[] {HwProbeApplet.WEI_TRANSIENT_K8, HwProbeApplet.WEI_TRANSIENT_K1, HwProbeApplet.WEI_PERSISTENT_K8}) {
      assertArrayEquals(expected, assertPass(run(HwProbeApplet.INS_WEI25519, variant)), "variant " + variant);
    }
  }

  @Test
  @DisplayName("secp256k1 control matches BouncyCastle")
  void secp256k1() {
    X9ECParameters k1 = CustomNamedCurves.getByName("secp256k1");
    byte[] expected = k1.getG().multiply(scalar()).normalize().getEncoded(false);
    assertArrayEquals(expected, HwProbeApplet.K1_EXPECTED);
    assertArrayEquals(expected, assertPass(run(HwProbeApplet.INS_SECP256K1, 0)));
  }

  @Test
  @DisplayName("RUN_ALL returns one passing 7-byte summary row per probe")
  void runAll() {
    byte[] rows = run(HwProbeApplet.INS_RUN_ALL, 0);
    byte[][] expectedIds = {
        {HwProbeApplet.INS_RSA_256, 0}, {HwProbeApplet.INS_RSA_512, 0},
        {HwProbeApplet.INS_WEI25519, HwProbeApplet.WEI_TRANSIENT_K8},
        {HwProbeApplet.INS_WEI25519, HwProbeApplet.WEI_TRANSIENT_K1},
        {HwProbeApplet.INS_WEI25519, HwProbeApplet.WEI_PERSISTENT_K8},
        {HwProbeApplet.INS_SECP256K1, 0}};
    assertEquals(expectedIds.length * HwProbeApplet.SUMMARY_ROW_LEN, rows.length);

    for (int i = 0; i < expectedIds.length; i++) {
      byte[] row = Arrays.copyOfRange(rows, i * HwProbeApplet.SUMMARY_ROW_LEN, (i + 1) * HwProbeApplet.SUMMARY_ROW_LEN);
      assertArrayEquals(new byte[] {expectedIds[i][0], expectedIds[i][1], HwProbeApplet.STATUS_PASS,
          HwProbeApplet.STAGE_COMPUTE, HwProbeApplet.EXC_NONE, 0, 0}, row, "row " + i);
    }
  }

  @Test
  @DisplayName("Unknown Wei25519 variant is rejected with SW_INCORRECT_P1P2, not reported as a probe failure")
  void badVariant() {
    ResponseAPDU resp = sim.transmitCommand(new CommandAPDU(0x00, HwProbeApplet.INS_WEI25519, 0x7f, 0, 256));
    assertEquals(ISO7816.SW_INCORRECT_P1P2 & 0xffff, resp.getSW());
  }
}
