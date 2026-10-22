package im.status.keycard.probe;

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.SystemException;
import javacard.framework.Util;
import javacard.security.CryptoException;
import javacard.security.ECPrivateKey;
import javacard.security.KeyAgreement;
import javacard.security.KeyBuilder;
import javacard.security.RSAPrivateKey;
import javacard.security.RSAPublicKey;
import javacardx.crypto.Cipher;

/**
 * Hardware feasibility probe for the software Ed25519 core (Ed25519.java). Tests the two primitives
 * AlgTest does not cover, exactly as Ed25519 allocates and uses them, plus controls:
 *
 *   INS 0x10  256-bit RSA public key + ALG_RSA_NOPAD, modulus p = 2^255-19, exponent p-2
 *             (modular inversion). Input 2, expected (p+1)/2.
 *   INS 0x11  Control: 512-bit RSA public key + ALG_RSA_NOPAD (a size AlgTest reports as supported).
 *   INS 0x12  Fallback for 0x10, the same inversion as JCMathLib runs it on JCOP4 P71: a 512-bit key
 *             whose modulus is p zero-padded to 64 bytes (RSA_RESIZE_MOD). P1 selects the key:
 *             0x00 = TYPE_RSA_PRIVATE (JCMathLib's JCOP4_P71 config), 0x01 = TYPE_RSA_PUBLIC
 *   INS 0x20  ALG_EC_SVDP_DH_PLAIN_XY on the custom Wei25519 curve. P1 selects the variant:
 *             0x00 = TYPE_EC_FP_PRIVATE_TRANSIENT_DESELECT, cofactor 8 (what Ed25519 uses)
 *             0x01 = same transient key, cofactor 1
 *             0x02 = TYPE_EC_FP_PRIVATE (persistent), cofactor 8
 *             0x03 = transient key, cofactor never set (JCMathLib's JCOP4_P71 config)
 *   INS 0x30  Control: ALG_EC_SVDP_DH_PLAIN_XY on secp256k1 (known to work on JCOP: stock Keycard).
 *   INS 0x40  ALG_EC_PACE_GM (S*G + H, JCMathLib's hardware point addition) on Wei25519, computing
 *             SCALAR*G + G. Needed for a cheap on-card verify-after-sign. P1 selects the key:
 *             0x00 = transient, cofactor never set (JCMathLib's config), 0x01 = transient, cofactor 8,
 *             0x02 = transient, cofactor 1 (the only Wei25519 cofactor JCOP4 P71 accepts for PLAIN_XY)
 *   INS 0x01  Info: JCSystem.getVersion() and the probe version.
 *   INS 0x03  Free memory, as three 4-byte big-endian ints (JCSystem.getAvailableMemory, the
 *             JC 3.0.4 overload that is not capped at 32767): persistent, transient reset,
 *             transient deselect. Read it before INS 0x02, which allocates and caches objects.
 *   INS 0x02  Runs every probe above and returns a 7-byte summary row per probe.
 *
 * Nothing is allocated at install time, so the applet installs even when a key size is refused.
 * Objects are allocated on first use and cached. Every probe answers SW 9000 with a result record:
 *
 *   [status][stage][excType][reason (2)][outLen][out...]
 *
 *   status:  0x00 PASS, 0x01 WRONG_RESULT (computed but did not match the expected value),
 *            0x02 EXCEPTION
 *   stage:   0x01 allocate (getInstance/buildKey), 0x02 set key material/curve,
 *            0x03 init, 0x04 compute
 *   excType: 0x00 none, 0x01 CryptoException, 0x02 SystemException, 0x03 other RuntimeException
 *   reason:  CryptoException/SystemException reason code (e.g. CryptoException.ILLEGAL_VALUE = 1,
 *            NO_SUCH_ALGORITHM = 3), 0 otherwise
 *
 * Summary rows (INS 0x02) are [ins][p1][status][stage][excType][reason (2)].
 */
public class HwProbeApplet extends Applet {
  static final byte INS_INFO = (byte) 0x01;
  static final byte INS_RUN_ALL = (byte) 0x02;
  static final byte INS_MEMORY = (byte) 0x03;
  static final byte INS_RSA_256 = (byte) 0x10;
  static final byte INS_RSA_512 = (byte) 0x11;
  static final byte INS_RSA_512_INV = (byte) 0x12;
  static final byte INS_WEI25519 = (byte) 0x20;
  static final byte INS_SECP256K1 = (byte) 0x30;
  static final byte INS_PACE_GM = (byte) 0x40;

  static final byte RSA_INV_PRIVATE = 0x00;
  static final byte RSA_INV_PUBLIC = 0x01;

  static final byte WEI_TRANSIENT_K8 = 0x00;
  static final byte WEI_TRANSIENT_K1 = 0x01;
  static final byte WEI_PERSISTENT_K8 = 0x02;
  static final byte WEI_TRANSIENT_NO_K = 0x03;

  static final byte PACE_NO_K = 0x00;
  static final byte PACE_K8 = 0x01;
  static final byte PACE_K1 = 0x02;

  static final byte STATUS_PASS = 0x00;
  static final byte STATUS_WRONG_RESULT = 0x01;
  static final byte STATUS_EXCEPTION = 0x02;

  static final byte STAGE_ALLOCATE = 0x01;
  static final byte STAGE_SET = 0x02;
  static final byte STAGE_INIT = 0x03;
  static final byte STAGE_COMPUTE = 0x04;

  static final byte EXC_NONE = 0x00;
  static final byte EXC_CRYPTO = 0x01;
  static final byte EXC_SYSTEM = 0x02;
  static final byte EXC_OTHER = 0x03;

  static final byte PROBE_VERSION = 0x03;
  static final short HEADER_LEN = 6;
  static final short SUMMARY_ROW_LEN = 7;

  static final byte ALG_EC_SVDP_DH_PLAIN_XY = 6; // JavaCard 3.0.5 constant
  static final byte ALG_EC_PACE_GM = 5; // JavaCard 3.0.5 constant

  // p = 2^255 - 19
  static final byte[] WEI_P = {
      (byte) 0x7f, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
      (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
      (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
      (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xed
  };

  // p - 2, the Fermat inversion exponent
  static final byte[] P_MINUS_2 = {
      (byte) 0x7f, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
      (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
      (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
      (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xeb
  };

  // 2^-1 mod p = (p + 1) / 2
  static final byte[] INV_2 = {
      (byte) 0x3f, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
      (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
      (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
      (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xf7
  };

  static final byte[] WEI_A = {
      (byte) 0x2a, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa,
      (byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa,
      (byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa,
      (byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0x98, (byte) 0x49, (byte) 0x14, (byte) 0xa1, (byte) 0x44
  };

  static final byte[] WEI_B = {
      (byte) 0x7b, (byte) 0x42, (byte) 0x5e, (byte) 0xd0, (byte) 0x97, (byte) 0xb4, (byte) 0x25, (byte) 0xed,
      (byte) 0x09, (byte) 0x7b, (byte) 0x42, (byte) 0x5e, (byte) 0xd0, (byte) 0x97, (byte) 0xb4, (byte) 0x25,
      (byte) 0xed, (byte) 0x09, (byte) 0x7b, (byte) 0x42, (byte) 0x5e, (byte) 0xd0, (byte) 0x97, (byte) 0xb4,
      (byte) 0x26, (byte) 0x0b, (byte) 0x5e, (byte) 0x9c, (byte) 0x77, (byte) 0x10, (byte) 0xc8, (byte) 0x64
  };

  static final byte[] WEI_G = {
      (byte) 0x04, (byte) 0x2a, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa,
      (byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa,
      (byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa,
      (byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0xad, (byte) 0x24,
      (byte) 0x5a, (byte) 0x20, (byte) 0xae, (byte) 0x19, (byte) 0xa1, (byte) 0xb8, (byte) 0xa0, (byte) 0x86,
      (byte) 0xb4, (byte) 0xe0, (byte) 0x1e, (byte) 0xdd, (byte) 0x2c, (byte) 0x77, (byte) 0x48, (byte) 0xd1,
      (byte) 0x4c, (byte) 0x92, (byte) 0x3d, (byte) 0x4d, (byte) 0x7e, (byte) 0x6d, (byte) 0x7c, (byte) 0x61,
      (byte) 0xb2, (byte) 0x29, (byte) 0xe9, (byte) 0xc5, (byte) 0xa2, (byte) 0x7e, (byte) 0xce, (byte) 0xd3,
      (byte) 0xd9
  };

  // group order L = 2^252 + 27742317777372353535851937790883648493
  static final byte[] ED_L = {
      (byte) 0x10, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
      (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
      (byte) 0x14, (byte) 0xde, (byte) 0xf9, (byte) 0xde, (byte) 0xa2, (byte) 0xf7, (byte) 0x9c, (byte) 0xd6,
      (byte) 0x58, (byte) 0x12, (byte) 0x63, (byte) 0x1a, (byte) 0x5c, (byte) 0xf5, (byte) 0xd3, (byte) 0xed
  };

  static final byte[] K1_P = {
      (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
      (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
      (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
      (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xfe, (byte) 0xff, (byte) 0xff, (byte) 0xfc, (byte) 0x2f
  };

  static final byte[] K1_A = new byte[32];

  static final byte[] K1_B = {
      (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
      (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
      (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
      (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x07
  };

  static final byte[] K1_G = {
      (byte) 0x04, (byte) 0x79, (byte) 0xbe, (byte) 0x66, (byte) 0x7e, (byte) 0xf9, (byte) 0xdc, (byte) 0xbb,
      (byte) 0xac, (byte) 0x55, (byte) 0xa0, (byte) 0x62, (byte) 0x95, (byte) 0xce, (byte) 0x87, (byte) 0x0b,
      (byte) 0x07, (byte) 0x02, (byte) 0x9b, (byte) 0xfc, (byte) 0xdb, (byte) 0x2d, (byte) 0xce, (byte) 0x28,
      (byte) 0xd9, (byte) 0x59, (byte) 0xf2, (byte) 0x81, (byte) 0x5b, (byte) 0x16, (byte) 0xf8, (byte) 0x17,
      (byte) 0x98, (byte) 0x48, (byte) 0x3a, (byte) 0xda, (byte) 0x77, (byte) 0x26, (byte) 0xa3, (byte) 0xc4,
      (byte) 0x65, (byte) 0x5d, (byte) 0xa4, (byte) 0xfb, (byte) 0xfc, (byte) 0x0e, (byte) 0x11, (byte) 0x08,
      (byte) 0xa8, (byte) 0xfd, (byte) 0x17, (byte) 0xb4, (byte) 0x48, (byte) 0xa6, (byte) 0x85, (byte) 0x54,
      (byte) 0x19, (byte) 0x9c, (byte) 0x47, (byte) 0xd0, (byte) 0x8f, (byte) 0xfb, (byte) 0x10, (byte) 0xd4,
      (byte) 0xb8
  };

  static final byte[] K1_N = {
      (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
      (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xfe,
      (byte) 0xba, (byte) 0xae, (byte) 0xdc, (byte) 0xe6, (byte) 0xaf, (byte) 0x48, (byte) 0xa0, (byte) 0x3b,
      (byte) 0xbf, (byte) 0xd2, (byte) 0x5e, (byte) 0x8c, (byte) 0xd0, (byte) 0x36, (byte) 0x41, (byte) 0x41
  };

  // test scalar, below both L and the secp256k1 order
  static final byte[] SCALAR = {
      (byte) 0x01, (byte) 0x23, (byte) 0x45, (byte) 0x67, (byte) 0x89, (byte) 0xab, (byte) 0xcd, (byte) 0xef,
      (byte) 0xfe, (byte) 0xdc, (byte) 0xba, (byte) 0x98, (byte) 0x76, (byte) 0x54, (byte) 0x32, (byte) 0x10,
      (byte) 0x01, (byte) 0x23, (byte) 0x45, (byte) 0x67, (byte) 0x89, (byte) 0xab, (byte) 0xcd, (byte) 0xef,
      (byte) 0xfe, (byte) 0xdc, (byte) 0xba, (byte) 0x98, (byte) 0x76, (byte) 0x54, (byte) 0x32, (byte) 0x10
  };

  // SCALAR * WEI_G (uncompressed)
  static final byte[] WEI_EXPECTED = {
      (byte) 0x04, (byte) 0x35, (byte) 0x1a, (byte) 0x0c, (byte) 0xa1, (byte) 0xa8, (byte) 0xc2, (byte) 0x45,
      (byte) 0x6e, (byte) 0x34, (byte) 0x9e, (byte) 0x2b, (byte) 0xe8, (byte) 0x3a, (byte) 0x57, (byte) 0x80,
      (byte) 0xe6, (byte) 0x9b, (byte) 0x53, (byte) 0xd8, (byte) 0x55, (byte) 0xc6, (byte) 0xe4, (byte) 0x10,
      (byte) 0x5c, (byte) 0xaa, (byte) 0x37, (byte) 0xdc, (byte) 0x20, (byte) 0xd9, (byte) 0xdb, (byte) 0xed,
      (byte) 0xf5, (byte) 0x68, (byte) 0x52, (byte) 0x61, (byte) 0x9a, (byte) 0x64, (byte) 0x59, (byte) 0x24,
      (byte) 0x4d, (byte) 0xcf, (byte) 0xb5, (byte) 0x4e, (byte) 0x4d, (byte) 0xa3, (byte) 0xa8, (byte) 0x61,
      (byte) 0x7c, (byte) 0x5b, (byte) 0x41, (byte) 0x62, (byte) 0x03, (byte) 0x75, (byte) 0x49, (byte) 0xa8,
      (byte) 0x36, (byte) 0xae, (byte) 0x03, (byte) 0x71, (byte) 0xa2, (byte) 0x8b, (byte) 0xa8, (byte) 0xe6,
      (byte) 0xfb
  };

  // (SCALAR + 1) * WEI_G (uncompressed), i.e. SCALAR*G + G
  static final byte[] PACE_EXPECTED = {
      (byte) 0x04, (byte) 0x11, (byte) 0xf9, (byte) 0x5a, (byte) 0x02, (byte) 0xca, (byte) 0xf0, (byte) 0x76,
      (byte) 0x60, (byte) 0xb1, (byte) 0x27, (byte) 0x9d, (byte) 0x8e, (byte) 0x92, (byte) 0x82, (byte) 0x54,
      (byte) 0xe6, (byte) 0x2b, (byte) 0x63, (byte) 0x3b, (byte) 0x7c, (byte) 0x4f, (byte) 0xdb, (byte) 0x43,
      (byte) 0x40, (byte) 0x56, (byte) 0x70, (byte) 0x5f, (byte) 0x0b, (byte) 0xd5, (byte) 0x2c, (byte) 0x62,
      (byte) 0xcf, (byte) 0x3b, (byte) 0xee, (byte) 0x1e, (byte) 0xf5, (byte) 0xbd, (byte) 0x8f, (byte) 0xc7,
      (byte) 0x98, (byte) 0x1b, (byte) 0xff, (byte) 0xd3, (byte) 0x98, (byte) 0x22, (byte) 0x94, (byte) 0xf0,
      (byte) 0xb8, (byte) 0x86, (byte) 0x3c, (byte) 0xb8, (byte) 0x35, (byte) 0x5a, (byte) 0x79, (byte) 0x89,
      (byte) 0xad, (byte) 0x57, (byte) 0x83, (byte) 0x01, (byte) 0x9a, (byte) 0x42, (byte) 0xec, (byte) 0xdb,
      (byte) 0x97
  };

  // SCALAR * K1_G (uncompressed)
  static final byte[] K1_EXPECTED = {
      (byte) 0x04, (byte) 0xa8, (byte) 0x2f, (byte) 0x5a, (byte) 0x21, (byte) 0x7c, (byte) 0x54, (byte) 0x64,
      (byte) 0xfb, (byte) 0x81, (byte) 0xf9, (byte) 0x3c, (byte) 0xdf, (byte) 0x17, (byte) 0x3c, (byte) 0x16,
      (byte) 0x6b, (byte) 0xfa, (byte) 0x72, (byte) 0x6b, (byte) 0x42, (byte) 0x44, (byte) 0x39, (byte) 0xd4,
      (byte) 0x5c, (byte) 0x9f, (byte) 0x44, (byte) 0x74, (byte) 0x7d, (byte) 0x1c, (byte) 0x1a, (byte) 0x76,
      (byte) 0x5d, (byte) 0xe6, (byte) 0x3a, (byte) 0x02, (byte) 0xff, (byte) 0xbc, (byte) 0xb0, (byte) 0x26,
      (byte) 0x3b, (byte) 0x42, (byte) 0x86, (byte) 0xec, (byte) 0x35, (byte) 0xe8, (byte) 0x16, (byte) 0x16,
      (byte) 0xd8, (byte) 0xce, (byte) 0x36, (byte) 0x56, (byte) 0x95, (byte) 0x6b, (byte) 0x95, (byte) 0xfd,
      (byte) 0xe5, (byte) 0x86, (byte) 0xdb, (byte) 0x76, (byte) 0x18, (byte) 0x1d, (byte) 0x96, (byte) 0x56,
      (byte) 0x22
  };

  private Cipher rsaCipher;
  private RSAPublicKey rsa256;
  private RSAPublicKey rsa512;
  private RSAPrivateKey rsaInvPriv;
  private RSAPublicKey rsaInvPub;
  private KeyAgreement ecdh;
  private KeyAgreement pace;
  private ECPrivateKey weiTransient;
  private ECPrivateKey weiNoK;
  private ECPrivateKey weiPersistent;
  private ECPrivateKey k1Key;
  private byte[] work;
  private short[] mem;

  private byte stage;

  public static void install(byte[] bArray, short bOffset, byte bLength) {
    HwProbeApplet applet = new HwProbeApplet();
    if (bLength > 0 && bArray[bOffset] > 0) {
      applet.register(bArray, (short) (bOffset + 1), bArray[bOffset]);
    } else {
      applet.register();
    }
  }

  private short availableMemory(byte[] buf) {
    if (mem == null) {
      mem = JCSystem.makeTransientShortArray((short) 6, JCSystem.CLEAR_ON_DESELECT);
    }
    JCSystem.getAvailableMemory(mem, (short) 0, JCSystem.MEMORY_TYPE_PERSISTENT);
    JCSystem.getAvailableMemory(mem, (short) 2, JCSystem.MEMORY_TYPE_TRANSIENT_RESET);
    JCSystem.getAvailableMemory(mem, (short) 4, JCSystem.MEMORY_TYPE_TRANSIENT_DESELECT);
    for (short i = 0; i < 6; i++) {
      Util.setShort(buf, (short) (i * 2), mem[i]);
    }
    return 12;
  }

  public void process(APDU apdu) throws ISOException {
    if (selectingApplet()) {
      return;
    }

    byte[] buf = apdu.getBuffer();
    apdu.setIncomingAndReceive();
    short len;

    switch (buf[ISO7816.OFFSET_INS]) {
      case INS_INFO:
        Util.setShort(buf, (short) 0, JCSystem.getVersion());
        buf[2] = PROBE_VERSION;
        len = 3;
        break;
      case INS_RUN_ALL:
        len = runAll(buf);
        break;
      case INS_MEMORY:
        len = availableMemory(buf);
        break;
      case INS_RSA_256:
      case INS_RSA_512:
      case INS_RSA_512_INV:
      case INS_WEI25519:
      case INS_SECP256K1:
      case INS_PACE_GM:
        len = runProbe(buf[ISO7816.OFFSET_INS], buf[ISO7816.OFFSET_P1], buf, (short) 0);
        break;
      default:
        ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        return;
    }

    apdu.setOutgoingAndSend((short) 0, len);
  }

  private short runAll(byte[] buf) {
    short off = 0;
    off = summaryRow(INS_RSA_256, (byte) 0, buf, off);
    off = summaryRow(INS_RSA_512, (byte) 0, buf, off);
    off = summaryRow(INS_RSA_512_INV, RSA_INV_PRIVATE, buf, off);
    off = summaryRow(INS_RSA_512_INV, RSA_INV_PUBLIC, buf, off);
    off = summaryRow(INS_WEI25519, WEI_TRANSIENT_K8, buf, off);
    off = summaryRow(INS_WEI25519, WEI_TRANSIENT_K1, buf, off);
    off = summaryRow(INS_WEI25519, WEI_PERSISTENT_K8, buf, off);
    off = summaryRow(INS_WEI25519, WEI_TRANSIENT_NO_K, buf, off);
    off = summaryRow(INS_SECP256K1, (byte) 0, buf, off);
    off = summaryRow(INS_PACE_GM, PACE_NO_K, buf, off);
    off = summaryRow(INS_PACE_GM, PACE_K8, buf, off);
    off = summaryRow(INS_PACE_GM, PACE_K1, buf, off);
    return off;
  }

  private short summaryRow(byte ins, byte p1, byte[] buf, short off) {
    buf[off] = ins;
    buf[(short) (off + 1)] = p1;
    runProbe(ins, p1, buf, (short) (off + 2));
    // the record header's outLen byte (and any output) is overwritten by the next row
    return (short) (off + SUMMARY_ROW_LEN);
  }

  /**
   * Runs one probe and writes its result record at off. Returns the record length.
   */
  private short runProbe(byte ins, byte p1, byte[] buf, short off) {
    short outOff = (short) (off + HEADER_LEN);
    short outLen = 0;
    byte status;
    stage = STAGE_ALLOCATE;

    try {
      boolean match;

      switch (ins) {
        case INS_RSA_256:
          outLen = rsa256(buf, outOff);
          match = Util.arrayCompare(buf, outOff, INV_2, (short) 0, (short) INV_2.length) == 0;
          break;
        case INS_RSA_512:
          outLen = rsa512(buf, outOff);
          match = (outLen == 64) && (buf[(short) (outOff + 63)] == (byte) 0x08) && isZero(buf, outOff, (short) 63);
          break;
        case INS_RSA_512_INV:
          outLen = rsa512Inv(p1, buf, outOff);
          // numeric match: a card may return 64 bytes (zero-padded) or fewer; outLen is reported either way
          match = (outLen >= 32) && isZero(buf, outOff, (short) (outLen - 32))
              && Util.arrayCompare(buf, (short) (outOff + outLen - 32), INV_2, (short) 0, (short) 32) == 0;
          break;
        case INS_WEI25519:
          outLen = wei25519(p1, buf, outOff);
          match = Util.arrayCompare(buf, outOff, WEI_EXPECTED, (short) 0, (short) WEI_EXPECTED.length) == 0;
          break;
        case INS_PACE_GM:
          outLen = paceGm(p1, buf, outOff);
          match = Util.arrayCompare(buf, outOff, PACE_EXPECTED, (short) 0, (short) PACE_EXPECTED.length) == 0;
          break;
        default:
          outLen = secp256k1(buf, outOff);
          match = Util.arrayCompare(buf, outOff, K1_EXPECTED, (short) 0, (short) K1_EXPECTED.length) == 0;
          break;
      }

      status = match ? STATUS_PASS : STATUS_WRONG_RESULT;
      writeHeader(buf, off, status, EXC_NONE, (short) 0, outLen);
    } catch (ISOException e) {
      throw e;
    } catch (CryptoException e) {
      writeHeader(buf, off, STATUS_EXCEPTION, EXC_CRYPTO, e.getReason(), (short) 0);
    } catch (SystemException e) {
      writeHeader(buf, off, STATUS_EXCEPTION, EXC_SYSTEM, e.getReason(), (short) 0);
    } catch (RuntimeException e) {
      writeHeader(buf, off, STATUS_EXCEPTION, EXC_OTHER, (short) 0, (short) 0);
    }

    return (short) (HEADER_LEN + (buf[(short) (off + 5)] & 0xff));
  }

  private void writeHeader(byte[] buf, short off, byte status, byte excType, short reason, short outLen) {
    buf[off] = status;
    buf[(short) (off + 1)] = stage;
    buf[(short) (off + 2)] = excType;
    Util.setShort(buf, (short) (off + 3), reason);
    buf[(short) (off + 5)] = (byte) outLen;
  }

  private short rsa256(byte[] buf, short outOff) {
    allocateRsaCipher();
    if (rsa256 == null) {
      rsa256 = (RSAPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PUBLIC, (short) 256, false);
    }

    stage = STAGE_SET;
    rsa256.setModulus(WEI_P, (short) 0, (short) 32);
    rsa256.setExponent(P_MINUS_2, (short) 0, (short) 32);

    stage = STAGE_INIT;
    rsaCipher.init(rsa256, Cipher.MODE_ENCRYPT);

    stage = STAGE_COMPUTE;
    byte[] in = workBuffer();
    Util.arrayFillNonAtomic(in, (short) 0, (short) 32, (byte) 0);
    in[31] = 2;
    return rsaCipher.doFinal(in, (short) 0, (short) 32, buf, outOff);
  }

  private short rsa512(byte[] buf, short outOff) {
    allocateRsaCipher();
    if (rsa512 == null) {
      rsa512 = (RSAPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PUBLIC, KeyBuilder.LENGTH_RSA_512, false);
    }

    stage = STAGE_SET;
    // modulus 2^512 - 1, exponent 3: 2^3 = 8
    byte[] tmp = workBuffer();
    Util.arrayFillNonAtomic(tmp, (short) 0, (short) 64, (byte) 0xff);
    rsa512.setModulus(tmp, (short) 0, (short) 64);
    tmp[0] = 3;
    rsa512.setExponent(tmp, (short) 0, (short) 1);

    stage = STAGE_INIT;
    rsaCipher.init(rsa512, Cipher.MODE_ENCRYPT);

    stage = STAGE_COMPUTE;
    Util.arrayFillNonAtomic(tmp, (short) 0, (short) 64, (byte) 0);
    tmp[63] = 2;
    return rsaCipher.doFinal(tmp, (short) 0, (short) 64, buf, outOff);
  }

  private short rsa512Inv(byte p1, byte[] buf, short outOff) {
    if (p1 != RSA_INV_PRIVATE && p1 != RSA_INV_PUBLIC) {
      ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
    }

    allocateRsaCipher();
    if (p1 == RSA_INV_PRIVATE && rsaInvPriv == null) {
      rsaInvPriv = (RSAPrivateKey) KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PRIVATE, KeyBuilder.LENGTH_RSA_512, false);
    } else if (p1 == RSA_INV_PUBLIC && rsaInvPub == null) {
      rsaInvPub = (RSAPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PUBLIC, KeyBuilder.LENGTH_RSA_512, false);
    }

    stage = STAGE_SET;
    // modulus: 32 zero bytes || p
    byte[] tmp = workBuffer();
    Util.arrayFillNonAtomic(tmp, (short) 0, (short) 32, (byte) 0);
    Util.arrayCopyNonAtomic(WEI_P, (short) 0, tmp, (short) 32, (short) 32);

    if (p1 == RSA_INV_PRIVATE) {
      rsaInvPriv.setModulus(tmp, (short) 0, (short) 64);
      rsaInvPriv.setExponent(P_MINUS_2, (short) 0, (short) 32);
      stage = STAGE_INIT;
      rsaCipher.init(rsaInvPriv, Cipher.MODE_DECRYPT);
    } else {
      rsaInvPub.setModulus(tmp, (short) 0, (short) 64);
      rsaInvPub.setExponent(P_MINUS_2, (short) 0, (short) 32);
      stage = STAGE_INIT;
      rsaCipher.init(rsaInvPub, Cipher.MODE_ENCRYPT);
    }

    stage = STAGE_COMPUTE;
    Util.arrayFillNonAtomic(tmp, (short) 0, (short) 64, (byte) 0);
    tmp[63] = 2;
    return rsaCipher.doFinal(tmp, (short) 0, (short) 64, buf, outOff);
  }

  private short wei25519(byte p1, byte[] buf, short outOff) {
    allocateEcdh();
    ECPrivateKey key;

    if (p1 == WEI_PERSISTENT_K8) {
      if (weiPersistent == null) {
        weiPersistent = (ECPrivateKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PRIVATE, (short) 256, false);
      }
      key = weiPersistent;
    } else if (p1 == WEI_TRANSIENT_K8 || p1 == WEI_TRANSIENT_K1) {
      key = transientWeiKey(true);
    } else if (p1 == WEI_TRANSIENT_NO_K) {
      key = transientWeiKey(false);
    } else {
      ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
      return 0;
    }

    stage = STAGE_SET;
    if (p1 == WEI_TRANSIENT_NO_K) {
      setWeiParameters(key, (short) 0);
    } else {
      setWeiParameters(key, p1 == WEI_TRANSIENT_K1 ? (short) 1 : (short) 8);
    }

    return scalarMult(key, WEI_G, buf, outOff);
  }

  private short paceGm(byte p1, byte[] buf, short outOff) {
    if (pace == null) {
      pace = KeyAgreement.getInstance(ALG_EC_PACE_GM, false);
    }

    ECPrivateKey key;
    if (p1 == PACE_NO_K) {
      key = transientWeiKey(false);
    } else if (p1 == PACE_K8 || p1 == PACE_K1) {
      key = transientWeiKey(true);
    } else {
      ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
      return 0;
    }

    stage = STAGE_SET;
    setWeiParameters(key, p1 == PACE_K8 ? (short) 8 : p1 == PACE_K1 ? (short) 1 : (short) 0);

    stage = STAGE_INIT;
    pace.init(key);

    stage = STAGE_COMPUTE;
    // S*G + H with H = G
    return pace.generateSecret(WEI_G, (short) 0, (short) WEI_G.length, buf, outOff);
  }

  /**
   * Returns a transient Wei25519 key. The cofactor-setting and never-set variants use separate
   * objects, so a cofactor set by one probe cannot leak into the other.
   */
  private ECPrivateKey transientWeiKey(boolean setsCofactor) {
    if (setsCofactor) {
      if (weiTransient == null) {
        weiTransient = (ECPrivateKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PRIVATE_TRANSIENT_DESELECT, (short) 256, false);
      }
      return weiTransient;
    }

    if (weiNoK == null) {
      weiNoK = (ECPrivateKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PRIVATE_TRANSIENT_DESELECT, (short) 256, false);
    }
    return weiNoK;
  }

  /**
   * Sets the Wei25519 domain parameters and SCALAR. A cofactor of 0 means setK is not called.
   */
  private static void setWeiParameters(ECPrivateKey key, short cofactor) {
    key.setFieldFP(WEI_P, (short) 0, (short) 32);
    key.setA(WEI_A, (short) 0, (short) 32);
    key.setB(WEI_B, (short) 0, (short) 32);
    key.setG(WEI_G, (short) 0, (short) WEI_G.length);
    key.setR(ED_L, (short) 0, (short) 32);
    if (cofactor != 0) {
      key.setK(cofactor);
    }
    key.setS(SCALAR, (short) 0, (short) 32);
  }

  private short secp256k1(byte[] buf, short outOff) {
    allocateEcdh();
    if (k1Key == null) {
      k1Key = (ECPrivateKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PRIVATE_TRANSIENT_DESELECT, (short) 256, false);
    }

    stage = STAGE_SET;
    k1Key.setFieldFP(K1_P, (short) 0, (short) 32);
    k1Key.setA(K1_A, (short) 0, (short) 32);
    k1Key.setB(K1_B, (short) 0, (short) 32);
    k1Key.setG(K1_G, (short) 0, (short) K1_G.length);
    k1Key.setR(K1_N, (short) 0, (short) 32);
    k1Key.setK((short) 1);
    k1Key.setS(SCALAR, (short) 0, (short) 32);

    return scalarMult(k1Key, K1_G, buf, outOff);
  }

  private short scalarMult(ECPrivateKey key, byte[] point, byte[] buf, short outOff) {
    stage = STAGE_INIT;
    ecdh.init(key);

    stage = STAGE_COMPUTE;
    return ecdh.generateSecret(point, (short) 0, (short) point.length, buf, outOff);
  }

  private void allocateRsaCipher() {
    if (rsaCipher == null) {
      rsaCipher = Cipher.getInstance(Cipher.ALG_RSA_NOPAD, false);
    }
  }

  private void allocateEcdh() {
    if (ecdh == null) {
      ecdh = KeyAgreement.getInstance(ALG_EC_SVDP_DH_PLAIN_XY, false);
    }
  }

  private byte[] workBuffer() {
    if (work == null) {
      work = JCSystem.makeTransientByteArray((short) 64, JCSystem.CLEAR_ON_DESELECT);
    }
    return work;
  }

  private static boolean isZero(byte[] buf, short off, short len) {
    for (short i = 0; i < len; i++) {
      if (buf[(short) (off + i)] != 0) {
        return false;
      }
    }
    return true;
  }
}
