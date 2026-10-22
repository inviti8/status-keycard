package im.status.keycard;

import com.licel.jcardsim.smartcardio.CardSimulator;
import com.licel.jcardsim.smartcardio.CardTerminalSimulator;
import com.licel.jcardsim.utils.AIDUtil;
import im.status.keycard.applet.Certificate;
import im.status.keycard.applet.IdentCommandSet;
import im.status.keycard.applet.Identifiers;
import im.status.keycard.desktop.PCSCCardChannel;
import im.status.keycard.io.APDUResponse;
import im.status.keycard.notes.NoteStoreApplet;
import apdu4j.pcsc.TerminalManager;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import javax.smartcardio.CardTerminal;
import java.io.ByteArrayOutputStream;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/**
 * The note store (docs/NOTE_STORE.md) through the Keycard applet's secure channel. Runs on the simulator and on a
 * card (target "card": `./gradlew install` must have put the store and the fork on it).
 *
 * Every test starts from an empty store: both trees (main and duress PIN) are emptied by deleting their entries,
 * then the main PIN is verified.
 */
public class NoteStoreTest {
  static final boolean SIMULATOR = "simulator".equals(System.getProperty("im.status.keycard.test.target", "card"));

  static final String PIN = "000000";
  static final String DURESS_PIN = "024680";
  static final String PUK = "012345678901";

  static final byte[] NOTES_PACKAGE_AID = {(byte) 0xA0, 0x00, 0x00, 0x08, 0x04, 0x00, 0x03};
  static final byte[] NOTES_APPLET_AID = {(byte) 0xA0, 0x00, 0x00, 0x08, 0x04, 0x00, 0x03, 0x01};
  static final byte[] NOTES_INSTANCE_AID = {(byte) 0xA0, 0x00, 0x00, 0x08, 0x04, 0x00, 0x03, 0x01, 0x01};

  static final int SW_OK = 0x9000;
  static final int SW_WRONG_DATA = 0x6A80;
  static final int SW_FULL = 0x6A84;
  static final int SW_NOT_FOUND = 0x6A88;
  static final int SW_TAG_EXISTS = 0x6A89;
  static final int SW_CONDITIONS = 0x6985;

  /** Measured container size: ~692 B + 290 B per pair (kenter-wallet backup.rs). */
  static int noteSize(int pairs) {
    return 692 + 290 * pairs;
  }

  static final SecureRandom RANDOM = new SecureRandom();

  static Rig shared;
  Rig rig;

  @BeforeAll
  static void setupAll() throws Exception {
    shared = SIMULATOR ? Rig.simulator(null, true) : Rig.card();
  }

  @BeforeEach
  void setup() throws Exception {
    rig = shared;
    empty();
  }

  /** Empties both trees and leaves the main PIN verified. */
  void empty() throws Exception {
    rig.unlock();
    deleteAll();
    assertEquals(SW_OK, rig.cmdSet.verifyPIN(DURESS_PIN).getSw());
    deleteAll();
    assertEquals(SW_OK, rig.cmdSet.verifyPIN(PIN).getSw());
  }

  /** Deletes (or aborts) every entry the active PIN can see. */
  void deleteAll() throws Exception {
    int metaLen = status().metaLen;
    for (byte[] row : list(metaLen)) {
      boolean writing = row[1] == NoteStoreApplet.STATUS_WRITING;
      assertEquals(SW_OK, delete(row[0] & 0xff, writing, Arrays.copyOfRange(row, 4, 36)).getSw());
    }
  }

  // --- the rig: one card or simulator with the store, Keycard and Ident applets, unlocked over SC V2

  static class Rig {
    CardSimulator simulator;
    TestKeycardCommandSet cmdSet;
    java.security.KeyPair ca;
    boolean duressPin;

    static Rig simulator(byte[] storeParams, boolean duressPin) throws Exception {
      Rig r = new Rig();
      r.simulator = new CardSimulator();
      r.duressPin = duressPin;
      r.install(NOTES_APPLET_AID, NoteStoreApplet.class, NOTES_INSTANCE_AID, storeParams);
      r.installKeycard();
      r.install(Identifiers.IDENT_AID, IdentApplet.class, Identifiers.IDENT_INSTANCE_AID, new byte[] {0x01, 0x00, 0x02, (byte) 0xC9, 0x00});
      r.connect(CardTerminalSimulator.terminal(r.simulator));
      return r;
    }

    static Rig card() throws Exception {
      Rig r = new Rig();
      r.duressPin = true;
      CardTerminal terminal = null;
      for (CardTerminal t : TerminalManager.getTerminalFactory().terminals().list()) {
        if (t.isCardPresent()) {
          terminal = t;
          break;
        }
      }
      assertNotNull(terminal, "no PC/SC reader with a card present");
      r.connect(terminal);
      return r;
    }

    void installKeycard() throws Exception {
      install(Identifiers.KEYCARD_AID, KeycardApplet.class, Identifiers.getKeycardInstanceAID(), null);
    }

    /** Re-creates the Keycard instance after deleteApplet (jcardsim keeps the class loaded, so no installApplet). */
    void recreateKeycard() throws Exception {
      byte[] instanceAid = Identifiers.getKeycardInstanceAID();
      byte[] bArray = new byte[instanceAid.length + 1];
      bArray[0] = (byte) instanceAid.length;
      System.arraycopy(instanceAid, 0, bArray, 1, instanceAid.length);
      simulator.createApplet(AIDUtil.create(Identifiers.KEYCARD_AID), bArray, (short) 0, (byte) bArray.length);
    }

    void install(byte[] aid, Class<? extends javacard.framework.Applet> applet, byte[] instanceAid, byte[] params) throws Exception {
      ByteArrayOutputStream bos = new ByteArrayOutputStream();
      bos.write(instanceAid.length);
      bos.write(instanceAid);
      if (params != null) {
        bos.write(params);
      }
      simulator.installApplet(AIDUtil.create(aid), applet, bos.toByteArray(), (short) 0, (byte) bos.size());
    }

    void connect(CardTerminal terminal) throws Exception {
      PCSCCardChannel channel = new PCSCCardChannel(terminal.connect("*").getBasicChannel());
      ca = caKeyPair();
      IdentCommandSet idCmdSet = new IdentCommandSet(channel);
      idCmdSet.select().checkOK();
      idCmdSet.storeData(TestIdentity.certStoreData(ca)).checkSW(0x9000, 0x6985); // write-once
      byte[] caPub = ((org.bouncycastle.jce.interfaces.ECPublicKey) ca.getPublic()).getQ().getEncoded(true);
      cmdSet = new TestKeycardCommandSet(channel, caPub);
      initIfNeeded();
    }

    void initIfNeeded() throws Exception {
      cmdSet.select().checkOK();
      if (!cmdSet.getApplicationInfo().isInitializedCard()) {
        if (duressPin) {
          cmdSet.init(PIN, DURESS_PIN, PUK, new byte[0], (byte) 3, (byte) 5).checkOK();
        } else {
          cmdSet.init(PIN, PUK, new byte[0]).checkOK();
        }
      }
    }

    /** Selects, opens the secure channel and verifies the main PIN. */
    void unlock() throws Exception {
      cmdSet.select().checkOK();
      cmdSet.autoOpenSecureChannel();
      assertEquals(SW_OK, cmdSet.verifyPIN(PIN).getSw());
    }

    APDUResponse send(int ins, int p1, int p2, byte[] data) throws Exception {
      return cmdSet.send(ins, p1, p2, data);
    }

    static java.security.KeyPair caKeyPair() throws Exception {
      if (java.security.Security.getProvider("BC") == null) {
        java.security.Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
      }
      ECParameterSpec spec = ECNamedCurveTable.getParameterSpec("secp256k1");
      java.security.KeyFactory kf = java.security.KeyFactory.getInstance("EC", "BC");
      java.math.BigInteger priv = new java.math.BigInteger("a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2", 16);
      return new java.security.KeyPair(
          kf.generatePublic(new org.bouncycastle.jce.spec.ECPublicKeySpec(spec.getG().multiply(priv), spec)),
          kf.generatePrivate(new org.bouncycastle.jce.spec.ECPrivateKeySpec(priv, spec)));
    }
  }

  // --- command helpers

  static class Status {
    int version, blocksTotal, blocksFree, entriesTotal, entriesFree, metaLen;
  }

  Status status() throws Exception {
    APDUResponse r = rig.send(KeycardApplet.INS_NOTE_STATUS, 0, 0, new byte[0]);
    assertEquals(SW_OK, r.getSw());
    byte[] d = r.getData();
    assertEquals(8, d.length);
    Status s = new Status();
    s.version = d[0];
    s.blocksTotal = ((d[1] & 0xff) << 8) | (d[2] & 0xff);
    s.blocksFree = ((d[3] & 0xff) << 8) | (d[4] & 0xff);
    s.entriesTotal = d[5] & 0xff;
    s.entriesFree = d[6] & 0xff;
    s.metaLen = d[7];
    return s;
  }

  static byte[] tag() {
    byte[] t = new byte[32];
    RANDOM.nextBytes(t);
    return t;
  }

  static byte[] bytes(int len) {
    byte[] b = new byte[len];
    RANDOM.nextBytes(b);
    return b;
  }

  static byte[] sha256(byte[] data) throws Exception {
    return MessageDigest.getInstance("SHA-256").digest(data);
  }

  static byte[] concat(byte[]... parts) {
    ByteArrayOutputStream bos = new ByteArrayOutputStream();
    for (byte[] p : parts) {
      bos.write(p, 0, p.length);
    }
    return bos.toByteArray();
  }

  static byte[] u16(int v) {
    return new byte[] {(byte) (v >> 8), (byte) v};
  }

  APDUResponse begin(int len, byte[] tag, byte[] meta) throws Exception {
    return rig.send(KeycardApplet.INS_NOTE_BEGIN, 0, 0, concat(u16(len), tag, meta));
  }

  APDUResponse write(int entry, int offset, byte[] note, int from, int len) throws Exception {
    return rig.send(KeycardApplet.INS_NOTE_WRITE, entry, 0, concat(u16(offset), Arrays.copyOfRange(note, from, from + len)));
  }

  void writeAll(int entry, byte[] note) throws Exception {
    for (int off = 0; off < note.length; off += 240) {
      int n = Math.min(240, note.length - off);
      assertEquals(SW_OK, write(entry, off, note, off, n).getSw());
    }
  }

  APDUResponse commit(int entry, byte[] note) throws Exception {
    return rig.send(KeycardApplet.INS_NOTE_COMMIT, entry, 0, sha256(note));
  }

  /** BEGIN, WRITE all, COMMIT; returns the entry. */
  int store(byte[] note, byte[] tag, byte[] meta) throws Exception {
    APDUResponse r = begin(note.length, tag, meta);
    assertEquals(SW_OK, r.getSw());
    int entry = r.getData()[0] & 0xff;
    writeAll(entry, note);
    assertEquals(SW_OK, commit(entry, note).getSw());
    return entry;
  }

  byte[] readAll(int entry, int len) throws Exception {
    ByteArrayOutputStream bos = new ByteArrayOutputStream();
    for (int off = 0; off < len; off += 240) {
      APDUResponse r = rig.send(KeycardApplet.INS_NOTE_READ, entry, 0, concat(u16(off), new byte[] {(byte) Math.min(240, len - off)}));
      assertEquals(SW_OK, r.getSw());
      bos.write(r.getData(), 0, r.getData().length);
    }
    return bos.toByteArray();
  }

  /** LIST from entry 0 to the end; each row is [entry status len:2 tag:32 meta:M]. */
  java.util.List<byte[]> list(int metaLen) throws Exception {
    java.util.List<byte[]> rows = new java.util.ArrayList<>();
    int next = 0;
    while (next != 0xff) {
      APDUResponse r = rig.send(KeycardApplet.INS_NOTE_LIST, next, 0, new byte[0]);
      assertEquals(SW_OK, r.getSw());
      byte[] d = r.getData();
      int rec = 36 + metaLen;
      for (int off = 0; off + rec <= d.length - 1; off += rec) {
        rows.add(Arrays.copyOfRange(d, off, off + rec));
      }
      next = d[d.length - 1] & 0xff;
    }
    return rows;
  }

  APDUResponse delete(int entry, boolean abort, byte[] tag) throws Exception {
    return rig.send(KeycardApplet.INS_NOTE_DELETE, entry, abort ? KeycardApplet.NOTE_DELETE_P2_ABORT : 0, tag);
  }

  // --- tests

  @Test
  @DisplayName("STATUS of an empty store: J3R200 defaults")
  void emptyStatus() throws Exception {
    Status s = status();
    assertEquals(1, s.version);
    assertEquals(s.blocksTotal, s.blocksFree);
    assertEquals(s.entriesTotal, s.entriesFree);
    if (SIMULATOR) {
      assertEquals(248, s.blocksTotal);
      assertEquals(64, s.entriesTotal);
      assertEquals(16, s.metaLen);
    }
    assertEquals(0, list(s.metaLen).size());
  }

  @Test
  @DisplayName("a 3-pair note round-trips byte for byte, and LIST and STATUS reflect it")
  void roundTrip() throws Exception {
    byte[] note = bytes(noteSize(3));
    byte[] tag = tag();
    byte[] meta = bytes(16);
    int entry = store(note, tag, meta);

    assertArrayEquals(note, readAll(entry, note.length));

    java.util.List<byte[]> rows = list(16);
    assertEquals(1, rows.size());
    byte[] row = rows.get(0);
    assertEquals(entry, row[0] & 0xff);
    assertEquals(NoteStoreApplet.STATUS_HELD, row[1]);
    assertEquals(note.length, ((row[2] & 0xff) << 8) | (row[3] & 0xff));
    assertArrayEquals(tag, Arrays.copyOfRange(row, 4, 36));
    assertArrayEquals(meta, Arrays.copyOfRange(row, 36, 52));

    Status s = status();
    assertEquals(s.blocksTotal - (note.length + 255) / 256, s.blocksFree);
    assertEquals(s.entriesTotal - 1, s.entriesFree);
  }

  @Test
  @DisplayName("a torn upload resumes: chunks in any order, COMMIT refuses until every byte matches")
  void resumableWrite() throws Exception {
    byte[] note = bytes(noteSize(4));
    byte[] tag = tag();
    APDUResponse r = begin(note.length, tag, new byte[16]);
    assertEquals(SW_OK, r.getSw());
    int entry = r.getData()[0] & 0xff;

    // every chunk but the second, backwards
    for (int off = (note.length - 1) / 240 * 240; off >= 0; off -= 240) {
      if (off != 240) {
        assertEquals(SW_OK, write(entry, off, note, off, Math.min(240, note.length - off)).getSw());
      }
    }
    assertEquals(SW_WRONG_DATA, commit(entry, note).getSw());

    // the entry is still WRITING and listed as such, so a host can find and finish it
    java.util.List<byte[]> rows = list(16);
    assertEquals(1, rows.size());
    assertEquals(NoteStoreApplet.STATUS_WRITING, rows.get(0)[1]);
    assertEquals(SW_CONDITIONS, rig.send(KeycardApplet.INS_NOTE_READ, entry, 0, concat(u16(0), new byte[] {16})).getSw());

    assertEquals(SW_OK, write(entry, 240, note, 240, 240).getSw());
    assertEquals(SW_OK, commit(entry, note).getSw());
    assertArrayEquals(note, readAll(entry, note.length));
  }

  @Test
  @DisplayName("a tag already held is refused; after DELETE it can be stored again")
  void duplicateTag() throws Exception {
    byte[] note = bytes(noteSize(2));
    byte[] tag = tag();
    int entry = store(note, tag, new byte[16]);
    assertEquals(SW_TAG_EXISTS, begin(note.length, tag, new byte[16]).getSw());
    assertEquals(SW_OK, delete(entry, false, tag).getSw());
    store(note, tag, new byte[16]);
  }

  @Test
  @DisplayName("DELETE needs the matching tag and frees the blocks; the entry is then gone")
  void deleteByTag() throws Exception {
    byte[] note = bytes(noteSize(3));
    byte[] tag = tag();
    int entry = store(note, tag, new byte[16]);

    assertEquals(SW_CONDITIONS, delete(entry, false, tag()).getSw());
    assertEquals(SW_CONDITIONS, delete(entry, true, tag).getSw()); // abort applies to WRITING only
    assertEquals(SW_OK, delete(entry, false, tag).getSw());

    Status s = status();
    assertEquals(s.blocksTotal, s.blocksFree);
    assertEquals(SW_NOT_FOUND, rig.send(KeycardApplet.INS_NOTE_READ, entry, 0, concat(u16(0), new byte[] {16})).getSw());
    assertEquals(SW_NOT_FOUND, delete(entry, false, tag).getSw());
  }

  @Test
  @DisplayName("an unfinished upload can be aborted, freeing its blocks")
  void abortWriting() throws Exception {
    byte[] tag = tag();
    APDUResponse r = begin(noteSize(10), tag, new byte[16]);
    assertEquals(SW_OK, r.getSw());
    int entry = r.getData()[0] & 0xff;
    assertEquals(SW_OK, delete(entry, true, tag).getSw());
    Status s = status();
    assertEquals(s.blocksTotal, s.blocksFree);
    assertEquals(s.entriesTotal, s.entriesFree);
  }

  @Test
  @DisplayName("SET META replaces the meta of a held note, guarded by its tag")
  void setMeta() throws Exception {
    byte[] tag = tag();
    int entry = store(bytes(noteSize(2)), tag, new byte[16]);
    byte[] meta = bytes(16);
    assertEquals(SW_CONDITIONS, rig.send(KeycardApplet.INS_NOTE_SET_META, entry, 0, concat(tag(), meta)).getSw());
    assertEquals(SW_OK, rig.send(KeycardApplet.INS_NOTE_SET_META, entry, 0, concat(tag, meta)).getSw());
    assertArrayEquals(meta, Arrays.copyOfRange(list(16).get(0), 36, 52));
  }

  @Test
  @DisplayName("bad lengths and offsets are refused")
  void bounds() throws Exception {
    assertEquals(SW_WRONG_DATA, begin(0, tag(), new byte[16]).getSw());
    assertEquals(SW_WRONG_DATA, begin(NoteStoreApplet.MAX_NOTE_LEN + 1, tag(), new byte[16]).getSw());
    assertEquals(SW_WRONG_DATA, rig.send(KeycardApplet.INS_NOTE_BEGIN, 0, 0, concat(u16(100), tag(), new byte[15])).getSw());

    byte[] note = bytes(300);
    byte[] tag = tag();
    APDUResponse r = begin(note.length, tag, new byte[16]);
    int entry = r.getData()[0] & 0xff;
    assertEquals(SW_WRONG_DATA, write(entry, 200, bytes(240), 0, 101).getSw()); // past the end
    assertEquals(SW_NOT_FOUND, write(200, 0, note, 0, 10).getSw());             // no such entry
    assertEquals(SW_OK, delete(entry, true, tag).getSw());

    // the largest note fits and round-trips
    byte[] big = bytes(NoteStoreApplet.MAX_NOTE_LEN);
    int bigEntry = store(big, tag(), new byte[16]);
    assertArrayEquals(big, readAll(bigEntry, big.length));
  }

  @Test
  @DisplayName("every note command needs the PIN")
  void pinRequired() throws Exception {
    rig.cmdSet.select().checkOK();
    rig.cmdSet.autoOpenSecureChannel();
    assertEquals(SW_CONDITIONS, rig.send(KeycardApplet.INS_NOTE_STATUS, 0, 0, new byte[0]).getSw());
    assertEquals(SW_CONDITIONS, rig.send(KeycardApplet.INS_NOTE_LIST, 0, 0, new byte[0]).getSw());
    assertEquals(SW_CONDITIONS, begin(100, tag(), new byte[16]).getSw());
  }

  @Test
  @DisplayName("the duress PIN sees its own empty store; the main PIN's notes are hidden, not wiped")
  void duressHides() throws Exception {
    byte[][] notes = new byte[3][];
    byte[][] tags = new byte[3][];
    int[] entries = new int[3];
    for (int i = 0; i < 3; i++) {
      notes[i] = bytes(noteSize(3));
      tags[i] = tag();
      entries[i] = store(notes[i], tags[i], new byte[16]);
    }
    Status mainStatus = status();

    assertEquals(SW_OK, rig.cmdSet.verifyPIN(DURESS_PIN).getSw());
    Status s = status();
    assertEquals(s.blocksTotal, s.blocksFree, "an empty tree reads as an empty store");
    assertEquals(s.entriesTotal, s.entriesFree);
    assertEquals(mainStatus.blocksTotal - 3 * 7, s.blocksTotal);
    assertEquals(0, list(16).size());
    // the main notes are unreachable by index, and their tags are not compared (no existence oracle)
    assertEquals(SW_NOT_FOUND, rig.send(KeycardApplet.INS_NOTE_READ, entries[0], 0, concat(u16(0), new byte[] {16})).getSw());
    assertEquals(SW_NOT_FOUND, delete(entries[0], false, tags[0]).getSw());
    byte[] decoy = bytes(noteSize(2));
    int decoyEntry = store(decoy, tags[0], new byte[16]);
    assertEquals(1, list(16).size());

    assertEquals(SW_OK, rig.cmdSet.verifyPIN(PIN).getSw());
    java.util.List<byte[]> rows = list(16);
    assertEquals(3, rows.size(), "the decoy note is not visible to the main PIN");
    for (int i = 0; i < 3; i++) {
      assertArrayEquals(notes[i], readAll(entries[i], notes[i].length));
    }
    assertEquals(SW_NOT_FOUND, rig.send(KeycardApplet.INS_NOTE_READ, decoyEntry, 0, concat(u16(0), new byte[] {16})).getSw());
  }

  @Test
  @DisplayName("capacity at the realistic note sizes: fill until full, then report")
  void capacity() throws Exception {
    Status empty = status();
    StringBuilder report = new StringBuilder("[notes] capacity, " + empty.blocksTotal + " blocks / " + empty.entriesTotal + " entries:");
    for (int pairs : new int[] {2, 3, 4, 10, 24}) {
      empty();
      byte[] note = bytes(noteSize(pairs));
      int stored = 0;
      while (true) {
        APDUResponse r = begin(note.length, tag(), new byte[16]);
        if (r.getSw() == SW_FULL) {
          break;
        }
        assertEquals(SW_OK, r.getSw());
        int entry = r.getData()[0] & 0xff;
        writeAll(entry, note);
        assertEquals(SW_OK, commit(entry, note).getSw());
        stored++;
      }
      int perNote = (note.length + 255) / 256;
      int expected = Math.min(empty.blocksTotal / perNote, empty.entriesTotal);
      assertEquals(expected, stored, pairs + " pairs");
      report.append(String.format(" %d pairs (%d B) = %d notes;", pairs, note.length, stored));
    }
    System.out.println(report);
  }

  @Test
  @DisplayName("knowing the duress PIN does not give unlimited guesses at the main PIN")
  void duressPinDoesNotResetMainPinTries() throws Exception {
    assumeTrue(SIMULATOR);
    rig = Rig.simulator(null, true);
    rig.cmdSet.select().checkOK();
    rig.cmdSet.autoOpenSecureChannel();
    // two wrong guesses, then the duress PIN, repeated: the wrong guesses must keep counting against the main PIN
    for (int i = 0; i < 4; i++) {
      assertEquals(0x6300, rig.cmdSet.verifyPIN("111111").getSw() & 0xFF00);
      assertEquals(0x6300, rig.cmdSet.verifyPIN("222222").getSw() & 0xFF00);
      assertEquals(SW_OK, rig.cmdSet.verifyPIN(DURESS_PIN).getSw());
    }
    assertEquals(0x6300, rig.cmdSet.verifyPIN(PIN).getSw() & 0xFF00, "the main PIN must be blocked after 8 wrong guesses");
  }

  // --- simulator-only: these need a fresh card

  @Test
  @DisplayName("INIT refuses a duress PIN equal to the main PIN, explicit or defaulted from the PUK")
  void initRefusesDuressEqualToMain() throws Exception {
    assumeTrue(SIMULATOR);
    Rig r = new Rig();
    r.simulator = new CardSimulator();
    r.install(NOTES_APPLET_AID, NoteStoreApplet.class, NOTES_INSTANCE_AID, null);
    r.installKeycard();
    r.install(Identifiers.IDENT_AID, IdentApplet.class, Identifiers.IDENT_INSTANCE_AID, new byte[] {0x01, 0x00, 0x02, (byte) 0xC9, 0x00});
    r.duressPin = true;
    PCSCCardChannel channel = new PCSCCardChannel(CardTerminalSimulator.terminal(r.simulator).connect("*").getBasicChannel());
    r.ca = Rig.caKeyPair();
    new IdentCommandSet(channel).select().checkOK();
    new IdentCommandSet(channel).storeData(TestIdentity.certStoreData(r.ca)).checkSW(0x9000, 0x6985);
    r.cmdSet = new TestKeycardCommandSet(channel, ((org.bouncycastle.jce.interfaces.ECPublicKey) r.ca.getPublic()).getQ().getEncoded(true));
    r.cmdSet.select().checkOK();

    assertEquals(SW_WRONG_DATA, r.cmdSet.init(PIN, PIN, PUK, new byte[0], (byte) 3, (byte) 5).getSw());
    assertEquals(SW_WRONG_DATA, r.cmdSet.init("012345", PUK, new byte[0]).getSw()); // PUK starts with the PIN
    assertEquals(SW_OK, r.cmdSet.init(PIN, PUK, new byte[0]).getSw());           // duress PIN = "012345"
  }

  @Test
  @DisplayName("the main PIN cannot be changed to the duress PIN; a duress session may set its own PIN freely")
  void changePinRules() throws Exception {
    assumeTrue(SIMULATOR);
    rig = Rig.simulator(null, true);
    rig.unlock();
    assertEquals(SW_WRONG_DATA, rig.cmdSet.changePIN(KeycardApplet.CHANGE_PIN_P1_USER_PIN, DURESS_PIN).getSw());
    // the refused comparison did not use up the duress PIN's tries
    for (int i = 0; i < 5; i++) {
      assertEquals(SW_WRONG_DATA, rig.cmdSet.changePIN(KeycardApplet.CHANGE_PIN_P1_USER_PIN, DURESS_PIN).getSw());
    }
    assertEquals(SW_OK, rig.cmdSet.verifyPIN(DURESS_PIN).getSw());

    // in a duress session no comparison is made, so CHANGE PIN cannot be used to test guesses at the main PIN
    assertEquals(SW_OK, rig.cmdSet.changePIN(KeycardApplet.CHANGE_PIN_P1_USER_PIN, "135790").getSw());
    assertEquals(SW_OK, rig.cmdSet.changePIN(KeycardApplet.CHANGE_PIN_P1_USER_PIN, PIN).getSw());
  }

  @Test
  @DisplayName("install parameters set blocks, entries and meta length")
  void installParameters() throws Exception {
    assumeTrue(SIMULATOR);
    // [privLen priv][paramLen C9 len blocks:2 entries:1 metaLen:1]
    rig = Rig.simulator(new byte[] {0x01, 0x00, 0x06, (byte) 0xC9, 0x04, 0x00, 0x14, 0x03, 0x18}, true);
    empty();
    Status s = status();
    assertEquals(20, s.blocksTotal);
    assertEquals(3, s.entriesTotal);
    assertEquals(24, s.metaLen);

    byte[] meta = bytes(24);
    byte[] note = bytes(600);
    int entry = store(note, tag(), meta);
    assertArrayEquals(meta, Arrays.copyOfRange(list(24).get(0), 36, 60));
    store(bytes(10), tag(), new byte[24]);
    store(bytes(10), tag(), new byte[24]);
    assertEquals(SW_FULL, begin(10, tag(), new byte[24]).getSw()); // out of entries, not blocks
    assertArrayEquals(note, readAll(entry, note.length));
  }

  @Test
  @DisplayName("notes survive deleting and reinstalling the Keycard applet")
  void survivesKeycardReinstall() throws Exception {
    assumeTrue(SIMULATOR);
    rig = Rig.simulator(null, true);
    empty();
    byte[] note = bytes(noteSize(3));
    byte[] tag = tag();
    int entry = store(note, tag, new byte[16]);

    rig.simulator.deleteApplet(AIDUtil.create(Identifiers.getKeycardInstanceAID()));
    rig.recreateKeycard();
    rig.initIfNeeded(); // a reinstalled applet is uninitialized: the seed would be restored from the phrase
    rig.unlock();

    assertArrayEquals(note, readAll(entry, note.length));
    assertArrayEquals(tag, Arrays.copyOfRange(list(16).get(0), 4, 36));
  }

  @Test
  @DisplayName("FACTORY RESET wipes the store")
  void factoryResetWipes() throws Exception {
    assumeTrue(SIMULATOR);
    rig = Rig.simulator(null, true);
    empty();
    byte[] note = bytes(noteSize(2));
    int entry = store(note, tag(), new byte[16]);

    // without a verified PIN the reset is refused (6985) and the notes stay
    rig.cmdSet.select().checkOK();
    assertEquals(SW_CONDITIONS, rig.cmdSet.factoryReset().getSw());
    rig.unlock();
    assertArrayEquals(note, readAll(entry, note.length));

    rig.cmdSet.select().checkOK();
    rig.cmdSet.autoOpenSecureChannel();
    assertEquals(SW_OK, rig.cmdSet.verifyPIN(PIN).getSw());
    assertEquals(SW_OK, rig.cmdSet.factoryReset().getSw());

    rig.initIfNeeded();
    rig.unlock();
    assertEquals(0, list(16).size());
  }
}
