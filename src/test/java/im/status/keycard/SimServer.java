package im.status.keycard;

import com.licel.jcardsim.smartcardio.CardSimulator;
import com.licel.jcardsim.smartcardio.CardTerminalSimulator;
import com.licel.jcardsim.utils.AIDUtil;
import im.status.keycard.applet.Certificate;
import im.status.keycard.applet.IdentCommandSet;
import im.status.keycard.applet.Identifiers;
import im.status.keycard.desktop.PCSCCardChannel;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.spec.ECPrivateKeySpec;
import org.bouncycastle.jce.spec.ECPublicKeySpec;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.util.encoders.Hex;

import javax.smartcardio.Card;
import javax.smartcardio.CardChannel;
import javax.smartcardio.CardTerminal;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.Security;

/**
 * Runs the Keycard applet suite (including the Ed25519 fork) inside jcardsim and exposes it over a
 * TCP socket as a raw-APDU service, so an external client — e.g. the Kenter stellar-keycard Rust
 * crate — can drive the applet exactly as it would a physical card, with no hardware and no
 * GlobalPlatform brick risk.
 *
 * Wire protocol (framed, big-endian):
 *   client -> server:  u16 length, then <length> APDU command bytes
 *   server -> client:  u16 length, then <length> APDU response bytes (data || SW1 SW2)
 * A zero-length command frame requests a card reset (fresh RAM state); the server replies with a
 * zero-length frame.
 *
 * The four applets are installed and a fixed identity certificate is provisioned (the main applet
 * refuses commands until the Ident applet holds a valid cert). The CA public key that certificate
 * chains to is printed at startup and passed via --ca-out so the client can be configured to verify
 * the secure-channel transcript against it.
 *
 * Run via the Gradle `simServer` task (test runtime classpath, -noverify). Port defaults to 21345,
 * override with -Psim.port=NNN or the SIM_PORT env var.
 */
public class SimServer {
  // Same fixed CA key the test harness uses, so behaviour matches the test suite.
  private static final String CA_PRIV_HEX = "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2";

  private final CardSimulator simulator;

  private SimServer(CardSimulator simulator) {
    this.simulator = simulator;
  }

  public static void main(String[] args) throws Exception {
    if (Security.getProvider("BC") == null) {
      Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
    }

    int port = 21345;
    String portProp = System.getProperty("sim.port", System.getenv("SIM_PORT"));
    if (portProp != null && !portProp.isEmpty()) {
      port = Integer.parseInt(portProp.trim());
    }

    CardSimulator simulator = new CardSimulator();
    KeyPair caKeyPair = buildCaKeyPair();
    installApplets(simulator);
    provisionCertificate(simulator, caKeyPair);

    byte[] caPub = ((ECPublicKey) caKeyPair.getPublic()).getQ().getEncoded(true);
    System.out.println("[sim] applets installed, identity cert provisioned");
    System.out.println("[sim] CA public key (compressed): " + Hex.toHexString(caPub));
    System.out.println("[sim] listening on 127.0.0.1:" + port);

    new SimServer(simulator).serve(port);
  }

  private static KeyPair buildCaKeyPair() throws Exception {
    ECParameterSpec caSpec = ECNamedCurveTable.getParameterSpec("secp256k1");
    KeyFactory kf = KeyFactory.getInstance("EC", "BC");
    BigInteger caPriv = new BigInteger(CA_PRIV_HEX, 16);
    ECPrivateKeySpec caPrivSpec = new ECPrivateKeySpec(caPriv, caSpec);
    ECPublicKeySpec caPubSpec = new ECPublicKeySpec(caSpec.getG().multiply(caPriv), caSpec);
    return new KeyPair(kf.generatePublic(caPubSpec), kf.generatePrivate(caPrivSpec));
  }

  private static void installApplets(CardSimulator simulator) throws Exception {
    ByteArrayOutputStream bos = new ByteArrayOutputStream();

    javacard.framework.AID aid = AIDUtil.create(Identifiers.KEYCARD_AID);
    bos.write(Identifiers.getKeycardInstanceAID().length);
    bos.write(Identifiers.getKeycardInstanceAID());
    simulator.installApplet(aid, KeycardApplet.class, bos.toByteArray(), (short) 0, (byte) bos.size());
    bos.reset();

    aid = AIDUtil.create(Identifiers.NDEF_AID);
    bos.write(Identifiers.NDEF_INSTANCE_AID.length);
    bos.write(Identifiers.NDEF_INSTANCE_AID);
    bos.write(new byte[] {0x01, 0x00, 0x02, (byte) 0xC9, 0x00});
    simulator.installApplet(aid, NDEFApplet.class, bos.toByteArray(), (short) 0, (byte) bos.size());
    bos.reset();

    aid = AIDUtil.create(Identifiers.CASH_AID);
    bos.write(Identifiers.CASH_INSTANCE_AID.length);
    bos.write(Identifiers.CASH_INSTANCE_AID);
    bos.write(new byte[] {0x01, 0x00, 0x02, (byte) 0xC9, 0x00});
    simulator.installApplet(aid, CashApplet.class, bos.toByteArray(), (short) 0, (byte) bos.size());
    bos.reset();

    aid = AIDUtil.create(Identifiers.IDENT_AID);
    bos.write(Identifiers.IDENT_INSTANCE_AID.length);
    bos.write(Identifiers.IDENT_INSTANCE_AID);
    bos.write(new byte[] {0x01, 0x00, 0x02, (byte) 0xC9, 0x00});
    simulator.installApplet(aid, IdentApplet.class, bos.toByteArray(), (short) 0, (byte) bos.size());
    bos.reset();
  }

  private static void provisionCertificate(CardSimulator simulator, KeyPair caKeyPair) throws Exception {
    CardTerminal terminal = CardTerminalSimulator.terminal(simulator);
    Card card = terminal.connect("*");
    CardChannel channel = card.getBasicChannel();
    PCSCCardChannel sdkChannel = new PCSCCardChannel(channel);


    IdentCommandSet idCmdSet = new IdentCommandSet(sdkChannel);
    idCmdSet.select().checkOK();
    idCmdSet.storeData(TestIdentity.certStoreData(caKeyPair)).checkOK();
  }

  private void serve(int port) throws Exception {
    try (ServerSocket server = new ServerSocket(port, 0, java.net.InetAddress.getByName("127.0.0.1"))) {
      while (true) {
        try (Socket client = server.accept()) {
          client.setTcpNoDelay(true);
          System.out.println("[sim] client connected: " + client.getRemoteSocketAddress());
          handle(client);
          System.out.println("[sim] client disconnected");
        } catch (java.io.EOFException eof) {
          System.out.println("[sim] client disconnected");
        } catch (Exception e) {
          System.out.println("[sim] connection error: " + e);
        }
      }
    }
  }

  private void handle(Socket client) throws Exception {
    DataInputStream in = new DataInputStream(client.getInputStream());
    DataOutputStream out = new DataOutputStream(client.getOutputStream());

    while (true) {
      int len;
      try {
        len = in.readUnsignedShort();
      } catch (java.io.EOFException eof) {
        return;
      }

      if (len == 0) {
        simulator.reset();
        out.writeShort(0);
        out.flush();
        continue;
      }

      byte[] cmd = new byte[len];
      in.readFully(cmd);

      ResponseAPDU resp = simulator.transmitCommand(new CommandAPDU(cmd));
      byte[] respBytes = resp.getBytes();

      out.writeShort(respBytes.length);
      out.write(respBytes);
      out.flush();
    }
  }
}
