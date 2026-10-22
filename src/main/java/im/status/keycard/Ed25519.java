package im.status.keycard;

import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.ECKey;
import javacard.security.ECPrivateKey;
import javacard.security.KeyAgreement;
import javacard.security.KeyBuilder;
import javacard.security.RSAPrivateKey;
import javacardx.crypto.Cipher;

/**
 * Pure Ed25519 (RFC 8032) signing over a 32-byte precomputed hash, without native EdDSA support.
 *
 * Instead of software point arithmetic, scalar multiplication runs on the card's native EC engine
 * over Wei25519, the short-Weierstrass form of edwards25519 (birationally equivalent, same group).
 * The result is mapped back to Edwards coordinates and compressed. This is the approach used by
 * dufkan/JCEd25519 (MIT) and JCMathLib, proven on NXP JCOP4 (J3Rxxx) hardware and in jcardsim.
 *
 * Support needed from the platform:
 *  - KeyAgreement ALG_EC_SVDP_DH_PLAIN_XY (JavaCard 3.0.5) with custom Fp curve parameters
 *  - raw RSA (ALG_RSA_NOPAD) with a 512-bit private key whose modulus is p zero-padded to 64 bytes
 *    and whose exponent is p-2, used for the modular inversion mod p as x^(p-2) (Fermat), one
 *    cipher operation per inversion. JCOP4 P71 refuses 256-bit RSA keys and rejects the padded
 *    modulus on a public key; this is JCMathLib's RSA_RESIZE_MOD configuration for that chip.
 *  - BigNumberMath (keycard-math) for modular add/sub/mul/reduce on 256-bit operands
 *
 * All BigNumberMath state is big-endian; RFC 8032 wire format is little-endian. Byte order is
 * flipped at the boundaries only.
 */
class Ed25519 {
  private static final byte ALG_EC_SVDP_DH_PLAIN_XY = 6; // JavaCard 3.0.5 constant

  static final short ED25519_KEY_SIZE = 32;
  static final short ED25519_SIG_SIZE = 64;

  // SLIP-0010 master key derivation HMAC key
  static final byte[] KEY_ED25519_SEED = {'e', 'd', '2', '5', '5', '1', '9', ' ', 's', 'e', 'e', 'd'};

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

  // Wei25519 curve coefficient a
  static final byte[] WEI_A = {
      (byte) 0x2a, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa,
      (byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa,
      (byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa,
      (byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0x98, (byte) 0x49, (byte) 0x14, (byte) 0xa1, (byte) 0x44
  };

  // A/3 mod p where A = 486662 (Montgomery curve25519 coefficient); x_montgomery = x_wei - A/3
  static final byte[] MONT_A3 = {
      (byte) 0x2a, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa,
      (byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa,
      (byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa,
      (byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0xad, (byte) 0x24, (byte) 0x51
  };

  // Wei25519 curve coefficient b
  static final byte[] WEI_B = {
      (byte) 0x7b, (byte) 0x42, (byte) 0x5e, (byte) 0xd0, (byte) 0x97, (byte) 0xb4, (byte) 0x25, (byte) 0xed,
      (byte) 0x09, (byte) 0x7b, (byte) 0x42, (byte) 0x5e, (byte) 0xd0, (byte) 0x97, (byte) 0xb4, (byte) 0x25,
      (byte) 0xed, (byte) 0x09, (byte) 0x7b, (byte) 0x42, (byte) 0x5e, (byte) 0xd0, (byte) 0x97, (byte) 0xb4,
      (byte) 0x26, (byte) 0x0b, (byte) 0x5e, (byte) 0x9c, (byte) 0x77, (byte) 0x10, (byte) 0xc8, (byte) 0x64
  };

  // Wei25519 base point (uncompressed), maps to the Ed25519 base point
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

  // C = sqrt(-(A+2)) mod p, the Montgomery -> Edwards x-coordinate scale factor
  static final byte[] ED_C = {
      (byte) 0x70, (byte) 0xd9, (byte) 0x12, (byte) 0x0b, (byte) 0x9f, (byte) 0x5f, (byte) 0xf9, (byte) 0x44,
      (byte) 0x2d, (byte) 0x84, (byte) 0xf7, (byte) 0x23, (byte) 0xfc, (byte) 0x03, (byte) 0xb0, (byte) 0x81,
      (byte) 0x3a, (byte) 0x5e, (byte) 0x2c, (byte) 0x2e, (byte) 0xb4, (byte) 0x82, (byte) 0xe5, (byte) 0x7d,
      (byte) 0x33, (byte) 0x91, (byte) 0xfb, (byte) 0x55, (byte) 0x00, (byte) 0xba, (byte) 0x81, (byte) 0xe7
  };

  static final byte[] ONE = {
      (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
      (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
      (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
      (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x01
  };

  // transient work buffer layout
  private static final short S_OFF = 0;            // secret scalar s (BE, reduced mod L)
  private static final short PREFIX_OFF = 32;      // RFC 8032 nonce prefix
  private static final short R_SCALAR_OFF = 64;    // nonce scalar r (BE)
  private static final short K_SCALAR_OFF = 96;    // challenge k (BE), then S = k*s + r
  private static final short A_ENC_OFF = 128;      // compressed public key A
  private static final short R_ENC_OFF = 160;      // compressed nonce point R
  private static final short POINT_OFF = 192;      // Weierstrass point 04 || X || Y (65)
  private static final short T1_OFF = 257;         // field element temp
  private static final short T2_OFF = 289;         // field element temp
  private static final short H64_OFF = 321;        // SHA-512 output staging (64)
  private static final short HASH_OFF = 385;       // input hash copy (32)
  private static final short INV_OFF = 417;        // 64-byte RSA block for modInv
  private static final short WORK_SIZE = 481;

  private static final short INV_BLOCK = 64;

  private static final short POINT_X = POINT_OFF + 1;
  private static final short POINT_Y = POINT_OFF + 33;

  private KeyAgreement multiplier;
  private ECPrivateKey weiKey;
  private RSAPrivateKey invKey;
  private Cipher invCipher;
  private byte[] work;

  /**
   * Allocates all objects. Must be called exactly once, during applet installation.
   */
  Ed25519() {
    multiplier = KeyAgreement.getInstance(ALG_EC_SVDP_DH_PLAIN_XY, false);
    weiKey = (ECPrivateKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PRIVATE_TRANSIENT_DESELECT, (short) 256, false);
    work = JCSystem.makeTransientByteArray(WORK_SIZE, JCSystem.CLEAR_ON_DESELECT);
    invKey = (RSAPrivateKey) KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PRIVATE, KeyBuilder.LENGTH_RSA_512, false);
    // modulus: 32 zero bytes || p
    Util.arrayFillNonAtomic(work, INV_OFF, (short) 32, (byte) 0);
    Util.arrayCopyNonAtomic(WEI_P, (short) 0, work, (short) (INV_OFF + 32), (short) 32);
    invKey.setModulus(work, INV_OFF, INV_BLOCK);
    invKey.setExponent(P_MINUS_2, (short) 0, (short) 32);
    invCipher = Cipher.getInstance(Cipher.ALG_RSA_NOPAD, false);
  }

  /**
   * Re-installs the Wei25519 parameters on the transient key. Called on applet selection.
   */
  void onSelect() {
    setCurveParameters(weiKey);
  }

  static void setCurveParameters(ECKey key) {
    key.setFieldFP(WEI_P, (short) 0, (short) 32);
    key.setA(WEI_A, (short) 0, (short) 32);
    key.setB(WEI_B, (short) 0, (short) 32);
    key.setG(WEI_G, (short) 0, (short) WEI_G.length);
    key.setR(ED_L, (short) 0, (short) 32);
    // JCOP4 P71 rejects cofactor 8 on this curve (ILLEGAL_VALUE at init); ALG_EC_SVDP_DH_PLAIN_XY
    // does not use the cofactor, so 1 yields the same [s]P
    key.setK((short) 1);
  }

  /**
   * Signs a 32-byte hash with pure Ed25519 (RFC 8032, no prehash) and outputs both the compressed
   * public key and the 64-byte signature. Deterministic: no on-card randomness is consumed.
   *
   * @param crypto crypto utilities (SHA-512 and BigNumberMath are used)
   * @param secret the 32-byte Ed25519 secret key (RFC 8032 seed)
   * @param secOff offset of the secret
   * @param hash the 32-byte hash to sign
   * @param hashOff offset of the hash
   * @param pubOut output buffer for the 32-byte public key
   * @param pubOff offset in the public key buffer
   * @param sigOut output buffer for the 64-byte signature R || S
   * @param sigOff offset in the signature buffer
   * @return the signature length (64)
   */
  short signHash(Crypto crypto, byte[] secret, short secOff, byte[] hash, short hashOff, byte[] pubOut, short pubOff, byte[] sigOut, short sigOff) {
    Util.arrayCopyNonAtomic(hash, hashOff, work, HASH_OFF, (short) 32);

    expandSecret(crypto, secret, secOff);

    // A = s*B
    scalarMultBase(crypto, S_OFF, A_ENC_OFF);

    // r = SHA-512(prefix || M) mod L
    crypto.sha512.update(work, PREFIX_OFF, (short) 32);
    crypto.sha512.doFinal(work, HASH_OFF, (short) 32, work, H64_OFF);
    reduceWide(crypto, R_SCALAR_OFF);

    // R = r*B
    scalarMultBase(crypto, R_SCALAR_OFF, R_ENC_OFF);

    // k = SHA-512(R || A || M) mod L
    crypto.sha512.update(work, R_ENC_OFF, (short) 32);
    crypto.sha512.update(work, A_ENC_OFF, (short) 32);
    crypto.sha512.doFinal(work, HASH_OFF, (short) 32, work, H64_OFF);
    reduceWide(crypto, K_SCALAR_OFF);

    // S = k*s + r mod L
    crypto.bigMath.modMul(work, K_SCALAR_OFF, (short) 32, work, S_OFF, (short) 32, ED_L, (short) 0, (short) 32);
    crypto.bigMath.modAdd(work, K_SCALAR_OFF, (short) 32, work, R_SCALAR_OFF, (short) 32, ED_L, (short) 0, (short) 32);

    Util.arrayCopyNonAtomic(work, A_ENC_OFF, pubOut, pubOff, (short) 32);
    Util.arrayCopyNonAtomic(work, R_ENC_OFF, sigOut, sigOff, (short) 32);
    reverseInto(work, K_SCALAR_OFF, sigOut, (short) (sigOff + 32), (short) 32);

    return ED25519_SIG_SIZE;
  }

  /**
   * Derives the compressed Ed25519 public key for the given secret.
   *
   * @return the public key length (32)
   */
  short publicKey(Crypto crypto, byte[] secret, short secOff, byte[] pubOut, short pubOff) {
    expandSecret(crypto, secret, secOff);
    scalarMultBase(crypto, S_OFF, A_ENC_OFF);
    Util.arrayCopyNonAtomic(work, A_ENC_OFF, pubOut, pubOff, (short) 32);
    return ED25519_KEY_SIZE;
  }

  /**
   * SLIP-0010 ed25519 child key derivation: starting from the master key and chain code, applies
   * I = HMAC-SHA512(chain, 0x00 || key || index) for every path element. Only hardened elements
   * are defined for ed25519.
   *
   * @param crypto crypto utilities (HMAC-SHA512)
   * @param masterKey the 32-byte SLIP-0010 master key
   * @param masterChain the 32-byte SLIP-0010 master chain code
   * @param path the path elements (4-byte big-endian integers)
   * @param pathOff offset of the path
   * @param pathLen length of the path in bytes (multiple of 4)
   * @param scratch scratch buffer with at least 101 bytes available (37 message + 64 HMAC output;
   *                the HMAC key must not alias its output on the software HMAC fallback)
   * @param scratchOff offset in the scratch buffer
   * @param out output buffer receiving key (32) || chain (32)
   * @param outOff offset in the output buffer
   * @return true on success, false if the path contains a non-hardened element
   */
  boolean slip10Derive(Crypto crypto, byte[] masterKey, byte[] masterChain, byte[] path, short pathOff, short pathLen, byte[] scratch, short scratchOff, byte[] out, short outOff) {
    short hmacOut = (short) (scratchOff + 37);

    Util.arrayCopyNonAtomic(masterKey, (short) 0, out, outOff, (short) 32);
    Util.arrayCopyNonAtomic(masterChain, (short) 0, out, (short) (outOff + 32), (short) 32);

    for (short i = pathOff; i < (short) (pathOff + pathLen); i += 4) {
      if (!crypto.bip32IsHardened(path, i)) {
        return false;
      }

      scratch[scratchOff] = 0;
      Util.arrayCopyNonAtomic(out, outOff, scratch, (short) (scratchOff + 1), (short) 32);
      Util.arrayCopyNonAtomic(path, i, scratch, (short) (scratchOff + 33), (short) 4);
      crypto.hmacSHA512(out, (short) (outOff + 32), (short) 32, scratch, scratchOff, (short) 37, scratch, hmacOut);
      Util.arrayCopyNonAtomic(scratch, hmacOut, out, outOff, (short) 64);
    }

    return true;
  }

  /**
   * RFC 8032 secret expansion: h = SHA-512(secret); s = clamp(h[0..31]) as scalar; prefix = h[32..63].
   * The clamped scalar is reduced mod L so it is always a valid input for the EC engine; this changes
   * neither the public key nor the signature.
   */
  private void expandSecret(Crypto crypto, byte[] secret, short secOff) {
    crypto.sha512.doFinal(secret, secOff, (short) 32, work, H64_OFF);

    // clamp on the little-endian representation
    work[H64_OFF] &= (byte) 0xF8;
    work[(short) (H64_OFF + 31)] &= (byte) 0x7F;
    work[(short) (H64_OFF + 31)] |= (byte) 0x40;

    reverseInto(work, H64_OFF, work, S_OFF, (short) 32);
    crypto.bigMath.modRed(work, S_OFF, (short) 32, ED_L, (short) 0, (short) 32);

    Util.arrayCopyNonAtomic(work, (short) (H64_OFF + 32), work, PREFIX_OFF, (short) 32);
  }

  /**
   * Interprets the 64-byte little-endian SHA-512 output at H64_OFF as an integer, reduces it mod L
   * and stores the 32-byte big-endian result at dstOff.
   */
  private void reduceWide(Crypto crypto, short dstOff) {
    reverse(work, H64_OFF, (short) 64);
    crypto.bigMath.modRed(work, H64_OFF, (short) 64, ED_L, (short) 0, (short) 32);
    Util.arrayCopyNonAtomic(work, (short) (H64_OFF + 32), work, dstOff, (short) 32);
  }

  /**
   * Computes scalar*B on Wei25519 with the native EC engine and stores the compressed Edwards
   * encoding of the result at encOff in the work buffer.
   */
  private void scalarMultBase(Crypto crypto, short scalarOff, short encOff) {
    weiKey.setS(work, scalarOff, (short) 32);
    multiplier.init(weiKey);
    multiplier.generateSecret(WEI_G, (short) 0, (short) WEI_G.length, work, POINT_OFF);
    encodePoint(crypto, encOff);
  }

  /**
   * Converts the Weierstrass point at POINT_OFF (04 || X || Y) to its compressed Edwards encoding:
   * 32 bytes little-endian y with the parity of x in the top bit.
   *
   * With u = X - A/3 (the Montgomery x): ed_x = C*u/Y, ed_y = (u-1)/(u+1).
   */
  private void encodePoint(Crypto crypto, short encOff) {
    // ed_x parity
    Util.arrayCopyNonAtomic(work, POINT_X, work, T1_OFF, (short) 32);
    crypto.bigMath.modSub(work, T1_OFF, (short) 32, MONT_A3, (short) 0, (short) 32, WEI_P, (short) 0, (short) 32);
    Util.arrayCopyNonAtomic(work, POINT_Y, work, T2_OFF, (short) 32);
    modInv(T2_OFF);
    crypto.bigMath.modMul(work, T1_OFF, (short) 32, ED_C, (short) 0, (short) 32, WEI_P, (short) 0, (short) 32);
    crypto.bigMath.modMul(work, T1_OFF, (short) 32, work, T2_OFF, (short) 32, WEI_P, (short) 0, (short) 32);
    byte xParity = (byte) (work[(short) (T1_OFF + 31)] & (byte) 0x01);

    // ed_y = (u-1)/(u+1)
    Util.arrayCopyNonAtomic(work, POINT_X, work, T1_OFF, (short) 32);
    crypto.bigMath.modSub(work, T1_OFF, (short) 32, MONT_A3, (short) 0, (short) 32, WEI_P, (short) 0, (short) 32);
    Util.arrayCopyNonAtomic(work, T1_OFF, work, T2_OFF, (short) 32);
    crypto.bigMath.modAdd(work, T2_OFF, (short) 32, ONE, (short) 0, (short) 32, WEI_P, (short) 0, (short) 32);
    modInv(T2_OFF);
    crypto.bigMath.modSub(work, T1_OFF, (short) 32, ONE, (short) 0, (short) 32, WEI_P, (short) 0, (short) 32);
    crypto.bigMath.modMul(work, T1_OFF, (short) 32, work, T2_OFF, (short) 32, WEI_P, (short) 0, (short) 32);

    reverseInto(work, T1_OFF, work, encOff, (short) 32);
    work[(short) (encOff + 31)] |= (byte) (xParity << 7);
  }

  /**
   * In-place modular inversion mod p of the 32-byte value at off in the work buffer,
   * computed as x^(p-2) mod p with a single raw RSA operation.
   */
  private void modInv(short off) {
    Util.arrayFillNonAtomic(work, INV_OFF, (short) 32, (byte) 0);
    Util.arrayCopyNonAtomic(work, off, work, (short) (INV_OFF + 32), (short) 32);
    invCipher.init(invKey, Cipher.MODE_DECRYPT);
    short len = invCipher.doFinal(work, INV_OFF, INV_BLOCK, work, INV_OFF);

    // the result is < p, so it fits the low 32 bytes; some implementations strip leading zeroes
    if (len > 32) {
      Util.arrayCopyNonAtomic(work, (short) (INV_OFF + len - 32), work, off, (short) 32);
    } else {
      Util.arrayFillNonAtomic(work, off, (short) (32 - len), (byte) 0);
      Util.arrayCopyNonAtomic(work, INV_OFF, work, (short) (off + 32 - len), len);
    }
  }

  private static void reverse(byte[] buf, short off, short len) {
    for (short i = 0; i < (short) (len / 2); i++) {
      byte t = buf[(short) (off + i)];
      buf[(short) (off + i)] = buf[(short) (off + len - 1 - i)];
      buf[(short) (off + len - 1 - i)] = t;
    }
  }

  private static void reverseInto(byte[] src, short srcOff, byte[] dst, short dstOff, short len) {
    for (short i = 0; i < len; i++) {
      dst[(short) (dstOff + i)] = src[(short) (srcOff + len - 1 - i)];
    }
  }
}
