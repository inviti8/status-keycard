package im.status.keycard.notes;

import javacard.framework.AID;
import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.Shareable;
import javacard.framework.Util;

/**
 * On-card byte custody for opaque notes (docs/NOTE_STORE.md). A separate package so that it survives Keycard
 * applet reinstalls; it is reached only through {@link NoteStore}, handed out to the Keycard applet alone.
 *
 * Storage: a pool of 256-byte blocks, chained per note through {@code next}, and a directory of entries
 * {@code [status:1 epoch:2 len:2 first:2 tag:32 meta:M]}. There is no free list: a block is free when no live
 * entry's chain reaches it. An entry is live when its status is not FREE and its epoch is the current one, so a
 * wipe is a single epoch increment. Every state change is one atomic write.
 *
 * Install parameters (GP C9 data, all optional): {@code blocks:2 entries:1 metaLen:1}.
 */
public class NoteStoreApplet extends Applet implements NoteStore {
  static final byte STORE_VERSION = 1;

  static final short BLOCK_SIZE = 256;
  static final short BLOCK_SHIFT = 8;
  static final short BLOCKS_PER_ARRAY = 32;
  static final short ARRAY_SHIFT = 5;
  static final short MAX_NOTE_BLOCKS = 32;
  public static final short MAX_NOTE_LEN = (short) (MAX_NOTE_BLOCKS * BLOCK_SIZE);
  static final short CHAIN_END = 0x7FFF;
  static final short TAG_LEN = 32;

  static final short DEFAULT_BLOCKS = 248;
  static final byte DEFAULT_ENTRIES = 64;
  static final byte DEFAULT_META_LEN = 16;
  static final short MAX_BLOCKS = 1024;
  static final short MAX_ENTRIES = 254;
  static final byte MAX_META_LEN = 64;

  static final byte STATUS_FREE = 0;
  public static final byte STATUS_WRITING = 1;
  public static final byte STATUS_HELD = 2;

  static final short E_STATUS = 0;
  static final short E_EPOCH = 1;
  static final short E_LEN = 3;
  static final short E_FIRST = 5;
  static final short E_TAG = 7;
  static final short E_META = 39;

  static final short SW_NOT_FOUND = (short) 0x6A88;
  static final short SW_TAG_EXISTS = (short) 0x6A89;

  // the Keycard applet's AID; instance AIDs extend it. Other applets in the Keycard package (Cash, Ident) have no
  // PIN and do not get the interface.
  static final byte[] KEYCARD_APPLET_AID = {(byte) 0xA0, 0x00, 0x00, 0x08, 0x04, 0x00, 0x01, 0x01};

  private final short blocks;
  private final short entries;
  private final byte metaLen;
  private final short entrySize;
  private final byte[] dir;
  private final short[] next;
  private final Object[] pool;
  private short epoch;

  public static void install(byte[] bArray, short bOffset, byte bLength) {
    new NoteStoreApplet(bArray, bOffset, bLength);
  }

  private NoteStoreApplet(byte[] bArray, short bOffset, byte bLength) {
    short b = DEFAULT_BLOCKS;
    short e = DEFAULT_ENTRIES;
    byte m = DEFAULT_META_LEN;

    // [aidLen aid][privLen priv][paramLen [C9 len data]]; anything past the AID may be absent
    short end = (short) (bOffset + (bLength & 0xFF));
    short off = (short) (bOffset + bArray[bOffset] + 1);
    if (off < end) {
      off += (short) (bArray[off] + 1);
    }
    if ((short) (off + 3) <= end && bArray[(short) (off + 1)] == (byte) 0xC9) {
      short dataLen = (short) (bArray[(short) (off + 2)] & 0xFF);
      short data = (short) (off + 3);
      if (dataLen >= 4 && (short) (data + 4) <= end) {
        b = Util.getShort(bArray, data);
        e = (short) (bArray[(short) (data + 2)] & 0xFF);
        m = bArray[(short) (data + 3)];
      }
    }

    if (b < 1 || b > MAX_BLOCKS || e < 1 || e > MAX_ENTRIES || m < 0 || m > MAX_META_LEN) {
      ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    }

    blocks = b;
    entries = e;
    metaLen = m;
    entrySize = (short) (E_META + m);
    dir = new byte[(short) (e * entrySize)];
    next = new short[b];

    short arrays = (short) ((short) (b + BLOCKS_PER_ARRAY - 1) >> ARRAY_SHIFT);
    pool = new Object[arrays];
    for (short i = 0; i < arrays; i++) {
      short n = (short) (b - (short) (i << ARRAY_SHIFT));
      if (n > BLOCKS_PER_ARRAY) {
        n = BLOCKS_PER_ARRAY;
      }
      pool[i] = new byte[(short) (n << BLOCK_SHIFT)];
    }

    register(bArray, (short) (bOffset + 1), bArray[bOffset]);
  }

  public Shareable getShareableInterfaceObject(AID clientAID, byte parameter) {
    if (clientAID != null && clientAID.partialEquals(KEYCARD_APPLET_AID, (short) 0, (byte) KEYCARD_APPLET_AID.length)) {
      return this;
    }
    return null;
  }

  public void process(APDU apdu) throws ISOException {
    if (selectingApplet()) {
      return;
    }
    ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
  }

  // NoteStore

  public short status(byte[] buf, short off, short scratchOff) {
    short free = computeFree(buf, scratchOff);
    short liveEntries = 0;
    for (short e = 0; e < entries; e++) {
      if (isLive((short) (e * entrySize))) {
        liveEntries++;
      }
    }

    buf[off] = STORE_VERSION;
    Util.setShort(buf, (short) (off + 1), blocks);
    Util.setShort(buf, (short) (off + 3), free);
    buf[(short) (off + 5)] = (byte) entries;
    buf[(short) (off + 6)] = (byte) (entries - liveEntries);
    buf[(short) (off + 7)] = metaLen;
    return 8;
  }

  public short list(byte first, byte[] buf, short off, short maxLen) {
    short rec = (short) (4 + TAG_LEN + metaLen);
    short end = (short) (off + maxLen - 1);
    short out = off;
    short e = (short) (first & 0xFF);

    for (; e < entries; e++) {
      short eo = (short) (e * entrySize);
      if (!isLive(eo)) {
        continue;
      }
      if ((short) (out + rec) > end) {
        break;
      }
      buf[out] = (byte) e;
      buf[(short) (out + 1)] = dir[eo];
      Util.arrayCopyNonAtomic(dir, (short) (eo + E_LEN), buf, (short) (out + 2), (short) 2);
      Util.arrayCopyNonAtomic(dir, (short) (eo + E_TAG), buf, (short) (out + 4), (short) (TAG_LEN + metaLen));
      out += rec;
    }

    buf[out] = (byte) (e < entries ? e : 0xFF);
    return (short) (out - off + 1);
  }

  public byte begin(byte[] buf, short dataOff, short scratchOff) {
    short len = Util.getShort(buf, dataOff);
    short tagOff = (short) (dataOff + 2);

    if (len < 1 || len > MAX_NOTE_LEN) {
      ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    }
    if (scratchOff < (short) (tagOff + TAG_LEN + metaLen)) {
      ISOException.throwIt(ISO7816.SW_UNKNOWN);
    }

    short slot = -1;
    for (short e = 0; e < entries; e++) {
      short eo = (short) (e * entrySize);
      if (!isLive(eo)) {
        if (slot < 0) {
          slot = e;
        }
      } else if (Util.arrayCompare(dir, (short) (eo + E_TAG), buf, tagOff, TAG_LEN) == 0) {
        ISOException.throwIt(SW_TAG_EXISTS);
      }
    }

    short needed = blocksFor(len);
    if (slot < 0 || computeFree(buf, scratchOff) < needed) {
      ISOException.throwIt(ISO7816.SW_FILE_FULL);
    }

    // Chain free blocks. These cells stay unreachable, so free, until the entry below is written.
    short first = CHAIN_END;
    short prev = CHAIN_END;
    short count = 0;
    for (short b = 0; b < blocks && count < needed; b++) {
      if ((buf[(short) (scratchOff + (short) (b >> 3))] & (byte) (1 << (b & 7))) != 0) {
        continue;
      }
      if (prev == CHAIN_END) {
        first = b;
      } else {
        next[prev] = b;
      }
      prev = b;
      count++;
    }
    next[prev] = CHAIN_END;

    // Assemble the entry over the (no longer needed) bitmap, then publish it with one atomic copy.
    buf[scratchOff] = STATUS_WRITING;
    Util.setShort(buf, (short) (scratchOff + E_EPOCH), epoch);
    Util.setShort(buf, (short) (scratchOff + E_LEN), len);
    Util.setShort(buf, (short) (scratchOff + E_FIRST), first);
    Util.arrayCopyNonAtomic(buf, tagOff, buf, (short) (scratchOff + E_TAG), (short) (TAG_LEN + metaLen));
    Util.arrayCopy(buf, scratchOff, dir, (short) (slot * entrySize), entrySize);

    return (byte) slot;
  }

  public void write(byte entry, short offset, byte[] buf, short off, short len) {
    short eo = checkEntry(entry, STATUS_WRITING);
    short noteLen = Util.getShort(dir, (short) (eo + E_LEN));
    if (offset < 0 || len < 0 || (short) (offset + len) > noteLen) {
      ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    }
    copyNote(eo, offset, buf, off, len, true);
  }

  public short read(byte entry, boolean held, short offset, byte[] buf, short off, short len) {
    short eo = checkEntry(entry, held ? STATUS_HELD : STATUS_WRITING);
    short noteLen = Util.getShort(dir, (short) (eo + E_LEN));
    if (offset < 0 || offset > noteLen || len < 0) {
      ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    }
    if (len > (short) (noteLen - offset)) {
      len = (short) (noteLen - offset);
    }
    copyNote(eo, offset, buf, off, len, false);
    return len;
  }

  public short length(byte entry, boolean held) {
    return Util.getShort(dir, (short) (checkEntry(entry, held ? STATUS_HELD : STATUS_WRITING) + E_LEN));
  }

  public void commit(byte entry) {
    dir[checkEntry(entry, STATUS_WRITING)] = STATUS_HELD;
  }

  public void delete(byte entry, boolean abort, byte[] buf, short tagOff) {
    short eo = checkEntry(entry, abort ? STATUS_WRITING : STATUS_HELD);
    checkTag(eo, buf, tagOff);
    dir[eo] = STATUS_FREE;
  }

  public void setMeta(byte entry, byte[] buf, short tagOff) {
    short eo = checkEntry(entry, STATUS_HELD);
    checkTag(eo, buf, tagOff);
    Util.arrayCopy(buf, (short) (tagOff + TAG_LEN), dir, (short) (eo + E_META), metaLen);
  }

  public void wipe() {
    if (epoch == (short) 0xFFFF) {
      // the next epoch is 0 again: entries left over from epoch 0 must not come back
      for (short e = 0; e < entries; e++) {
        dir[(short) (e * entrySize)] = STATUS_FREE;
      }
    }
    epoch++;
  }

  public byte metaLength() {
    return metaLen;
  }

  // internals

  private boolean isLive(short eo) {
    return dir[eo] != STATUS_FREE && Util.getShort(dir, (short) (eo + E_EPOCH)) == epoch;
  }

  private short checkEntry(byte entry, byte status) {
    short e = (short) (entry & 0xFF);
    if (e >= entries) {
      ISOException.throwIt(SW_NOT_FOUND);
    }
    short eo = (short) (e * entrySize);
    if (!isLive(eo)) {
      ISOException.throwIt(SW_NOT_FOUND);
    }
    if (dir[eo] != status) {
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }
    return eo;
  }

  private void checkTag(short eo, byte[] buf, short tagOff) {
    if (Util.arrayCompare(dir, (short) (eo + E_TAG), buf, tagOff, TAG_LEN) != 0) {
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }
  }

  private static short blocksFor(short len) {
    return (short) ((short) (len + BLOCK_SIZE - 1) >> BLOCK_SHIFT);
  }

  /**
   * Marks every block reached by a live entry in a bitmap at scratchOff and returns the number of free blocks.
   */
  private short computeFree(byte[] buf, short scratchOff) {
    short bitmapLen = (short) ((short) (blocks + 7) >> 3);
    if ((short) (scratchOff + bitmapLen) > (short) buf.length) {
      ISOException.throwIt(ISO7816.SW_UNKNOWN);
    }
    Util.arrayFillNonAtomic(buf, scratchOff, bitmapLen, (byte) 0);

    short used = 0;
    for (short e = 0; e < entries; e++) {
      short eo = (short) (e * entrySize);
      if (!isLive(eo)) {
        continue;
      }
      short n = blocksFor(Util.getShort(dir, (short) (eo + E_LEN)));
      short b = Util.getShort(dir, (short) (eo + E_FIRST));
      for (short i = 0; i < n; i++) {
        short byteOff = (short) (scratchOff + (short) (b >> 3));
        buf[byteOff] = (byte) (buf[byteOff] | (byte) (1 << (b & 7)));
        b = next[b];
      }
      used += n;
    }
    return (short) (blocks - used);
  }

  /** Copies len bytes between a note (from offset) and buf (at off), in the direction given by toPool. */
  private void copyNote(short eo, short offset, byte[] buf, short off, short len, boolean toPool) {
    short b = Util.getShort(dir, (short) (eo + E_FIRST));
    for (short i = (short) (offset >> BLOCK_SHIFT); i > 0; i--) {
      b = next[b];
    }
    short within = (short) (offset & (BLOCK_SIZE - 1));

    while (len > 0) {
      short chunk = (short) (BLOCK_SIZE - within);
      if (chunk > len) {
        chunk = len;
      }
      byte[] arr = (byte[]) pool[(short) (b >> ARRAY_SHIFT)];
      short po = (short) ((short) ((b & (BLOCKS_PER_ARRAY - 1)) << BLOCK_SHIFT) + within);
      if (toPool) {
        Util.arrayCopyNonAtomic(buf, off, arr, po, chunk);
      } else {
        Util.arrayCopyNonAtomic(arr, po, buf, off, chunk);
      }
      off += chunk;
      len -= chunk;
      within = 0;
      b = next[b];
    }
  }
}
