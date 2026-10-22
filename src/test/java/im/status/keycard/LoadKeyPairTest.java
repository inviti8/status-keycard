package im.status.keycard;

import org.bouncycastle.jce.ECNamedCurveTable;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.security.KeyPairGenerator;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/**
 * LOAD KEY with a plain keypair (no chain code) must never read past the command data. It used to decide
 * "extended" from the byte after the private key, which under SC V2 is this command's own ciphertext tail: about 1
 * load in 256 failed with 6A80. Before the fix this test fails with probability about 1 - (255/256)^1500 = 99.7%.
 */
public class LoadKeyPairTest {
  @Test
  @DisplayName("1500 random plain keypairs all load")
  void randomKeypairsLoad() throws Exception {
    assumeTrue(NoteStoreTest.SIMULATOR);
    NoteStoreTest.Rig rig = NoteStoreTest.Rig.simulator(null, true);
    rig.unlock();
    KeyPairGenerator g = KeyPairGenerator.getInstance("ECDH", "BC");
    g.initialize(ECNamedCurveTable.getParameterSpec("secp256k1"));
    for (int i = 0; i < 1500; i++) {
      KeyPair kp = g.generateKeyPair();
      assertEquals(0x9000, rig.cmdSet.loadKey(kp).getSw(), "load " + i);
    }
  }
}
