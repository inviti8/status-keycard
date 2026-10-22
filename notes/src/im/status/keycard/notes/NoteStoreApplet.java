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
 * wipe is a single epoch increment. Every state change is one atomic write. The status byte's top bit records the
 * tree (main or duress PIN) that owns the note; each tree sees only its own.
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
  // the status byte's top bit marks a note written under the duress PIN (its own, decoy, tree)
  static final byte STATUS_TREE_DURESS = (byte) 0x80;
  static final byte STATUS_MASK = 0x7F;

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
  // The duress tree's fixed share (1/8, at least 1) of blocks and entries; the main tree gets the rest. Each tree's
  // STATUS depends only on its own notes, so the duress view never reveals how much the main tree holds.
  private final short duressBlocks;
  private final short duressEntries;
  private final byte metaLen;
  private final short entrySize;
  private final byte[] dir;
  private final short[] next;
  private final Object[] pool;
  // Owner-index counters, 4 bytes big-endian each: main tree at 0, duress tree at 4. The next index to hand out.
  private final byte[] counters;
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

    if (b < 2 || b > MAX_BLOCKS || e < 2 || e > MAX_ENTRIES || m < 0 || m > MAX_META_LEN) {
      ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    }

    blocks = b;
    entries = e;
    duressBlocks = (short) (b >= 16 ? b >> 3 : 1);
    duressEntries = (short) (e >= 16 ? e >> 3 : 1);
    metaLen = m;
    entrySize = (short) (E_META + m);
    dir = new byte[(short) (e * entrySize)];
    next = new short[b];
    counters = new byte[8];
    counters[3] = 1;
    counters[7] = 1;

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

  public short status(byte tree, byte[] buf, short off, short scratchOff) {
    // derived from this tree's notes alone: nothing about the other tree, not even its size, shows here
    short capBlocks = blockShare(tree);
    short capEntries = entryShare(tree);

    buf[off] = STORE_VERSION;
    Util.setShort(buf, (short) (off + 1), capBlocks);
    Util.setShort(buf, (short) (off + 3), (short) (capBlocks - usedBlocks(tree)));
    buf[(short) (off + 5)] = (byte) capEntries;
    buf[(short) (off + 6)] = (byte) (capEntries - usedEntries(tree));
    buf[(short) (off + 7)] = metaLen;
    return 8;
  }

  public short list(byte tree, byte first, byte[] buf, short off, short maxLen) {
    short rec = (short) (4 + TAG_LEN + metaLen);
    short end = (short) (off + maxLen - 1);
    short out = off;
    short e = (short) (first & 0xFF);

    for (; e < entries; e++) {
      short eo = (short) (e * entrySize);
      if (!ownedBy(eo, tree)) {
        continue;
      }
      if ((short) (out + rec) > end) {
        break;
      }
      buf[out] = (byte) e;
      buf[(short) (out + 1)] = (byte) (dir[eo] & STATUS_MASK);
      Util.arrayCopyNonAtomic(dir, (short) (eo + E_LEN), buf, (short) (out + 2), (short) 2);
      Util.arrayCopyNonAtomic(dir, (short) (eo + E_TAG), buf, (short) (out + 4), (short) (TAG_LEN + metaLen));
      out += rec;
    }

    buf[out] = (byte) (e < entries ? e : 0xFF);
    return (short) (out - off + 1);
  }

  public byte begin(byte tree, byte[] buf, short dataOff, short scratchOff) {
    short len = Util.getShort(buf, dataOff);
    short tagOff = (short) (dataOff + 2);

    if (len < 1 || len > MAX_NOTE_LEN) {
      ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    }
    if (scratchOff < (short) (tagOff + TAG_LEN + metaLen)) {
      ISOException.throwIt(ISO7816.SW_UNKNOWN);
    }

    // Tags are unique within a tree only: refusing a tag the other tree holds would reveal that note.
    short slot = -1;
    for (short e = 0; e < entries; e++) {
      short eo = (short) (e * entrySize);
      if (!isLive(eo)) {
        if (slot < 0) {
          slot = e;
        }
      } else if (ownedBy(eo, tree) && Util.arrayCompare(dir, (short) (eo + E_TAG), buf, tagOff, TAG_LEN) == 0) {
        ISOException.throwIt(SW_TAG_EXISTS);
      }
    }

    // The tree's share is the limit. The shares add up to the store, so a slot and the physical blocks exist whenever
    // the share has room; the checks below them are a safeguard.
    short needed = blocksFor(len);
    if (usedEntries(tree) >= entryShare(tree) || (short) (usedBlocks(tree) + needed) > blockShare(tree)) {
      ISOException.throwIt(ISO7816.SW_FILE_FULL);
    }
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
    buf[scratchOff] = (byte) (STATUS_WRITING | treeBit(tree));
    Util.setShort(buf, (short) (scratchOff + E_EPOCH), epoch);
    Util.setShort(buf, (short) (scratchOff + E_LEN), len);
    Util.setShort(buf, (short) (scratchOff + E_FIRST), first);
    Util.arrayCopyNonAtomic(buf, tagOff, buf, (short) (scratchOff + E_TAG), (short) (TAG_LEN + metaLen));
    Util.arrayCopy(buf, scratchOff, dir, (short) (slot * entrySize), entrySize);

    return (byte) slot;
  }

  public void write(byte tree, byte entry, short offset, byte[] buf, short off, short len) {
    short eo = checkEntry(tree, entry, STATUS_WRITING);
    short noteLen = Util.getShort(dir, (short) (eo + E_LEN));
    if (offset < 0 || len < 0 || (short) (offset + len) > noteLen) {
      ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    }
    copyNote(eo, offset, buf, off, len, true);
  }

  public short read(byte tree, byte entry, boolean held, short offset, byte[] buf, short off, short len) {
    short eo = checkEntry(tree, entry, held ? STATUS_HELD : STATUS_WRITING);
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

  public short length(byte tree, byte entry, boolean held) {
    return Util.getShort(dir, (short) (checkEntry(tree, entry, held ? STATUS_HELD : STATUS_WRITING) + E_LEN));
  }

  public void commit(byte tree, byte entry) {
    dir[checkEntry(tree, entry, STATUS_WRITING)] = (byte) (STATUS_HELD | treeBit(tree));
  }

  public void delete(byte tree, byte entry, boolean abort, byte[] buf, short tagOff) {
    short eo = checkEntry(tree, entry, abort ? STATUS_WRITING : STATUS_HELD);
    checkTag(eo, buf, tagOff);
    dir[eo] = STATUS_FREE;
  }

  public void setMeta(byte tree, byte entry, byte[] buf, short tagOff) {
    short eo = checkEntry(tree, entry, STATUS_HELD);
    checkTag(eo, buf, tagOff);
    Util.arrayCopy(buf, (short) (tagOff + TAG_LEN), dir, (short) (eo + E_META), metaLen);
  }

  public void nextIndex(byte tree, byte[] buf, short off) {
    short co = tree != 0 ? (short) 4 : (short) 0;
    // exhausted once the counter has passed 0x7FFFFFFF, the largest index a hardened path component can carry
    if (counters[co] < 0) {
      ISOException.throwIt(ISO7816.SW_FILE_FULL);
    }

    // buf[off..off+4) = the index handed out, buf[off+4..off+8) = the next one, persisted in one atomic copy
    Util.arrayCopyNonAtomic(counters, co, buf, off, (short) 4);
    Util.arrayCopyNonAtomic(counters, co, buf, (short) (off + 4), (short) 4);
    for (short i = (short) (off + 7); i >= (short) (off + 4); i--) {
      buf[i]++;
      if (buf[i] != 0) {
        break;
      }
    }
    Util.arrayCopy(buf, (short) (off + 4), counters, co, (short) 4);
  }

  public void advanceIndex(byte tree, byte[] buf, short off) {
    short co = tree != 0 ? (short) 4 : (short) 0;
    // at most 0x80000000: the value after the last index
    if (buf[off] < 0 && (buf[(short) (off + 1)] != 0 || buf[(short) (off + 2)] != 0 || buf[(short) (off + 3)] != 0 || buf[off] != (byte) 0x80)) {
      ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    }
    if (compareUnsigned(buf, off, counters, co) > 0) {
      Util.arrayCopy(buf, off, counters, co, (short) 4);
    }
    Util.arrayCopyNonAtomic(counters, co, buf, off, (short) 4);
  }

  /** Compares two 4-byte big-endian unsigned values: negative, zero or positive. */
  private static short compareUnsigned(byte[] a, short aOff, byte[] b, short bOff) {
    for (short i = 0; i < 4; i++) {
      short x = (short) (a[(short) (aOff + i)] & 0xFF);
      short y = (short) (b[(short) (bOff + i)] & 0xFF);
      if (x != y) {
        return (short) (x - y);
      }
    }
    return 0;
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

  private short blockShare(byte tree) {
    return tree != 0 ? duressBlocks : (short) (blocks - duressBlocks);
  }

  private short entryShare(byte tree) {
    return tree != 0 ? duressEntries : (short) (entries - duressEntries);
  }

  /** Blocks occupied by the tree's live notes. */
  private short usedBlocks(byte tree) {
    short b = 0;
    for (short e = 0; e < entries; e++) {
      short eo = (short) (e * entrySize);
      if (ownedBy(eo, tree)) {
        b += blocksFor(Util.getShort(dir, (short) (eo + E_LEN)));
      }
    }
    return b;
  }

  /** The tree's live notes. */
  private short usedEntries(byte tree) {
    short n = 0;
    for (short e = 0; e < entries; e++) {
      if (ownedBy((short) (e * entrySize), tree)) {
        n++;
      }
    }
    return n;
  }

  private static byte treeBit(byte tree) {
    return tree != 0 ? STATUS_TREE_DURESS : 0;
  }

  private boolean isLive(short eo) {
    return (dir[eo] & STATUS_MASK) != STATUS_FREE && Util.getShort(dir, (short) (eo + E_EPOCH)) == epoch;
  }

  private boolean ownedBy(short eo, byte tree) {
    return isLive(eo) && (byte) (dir[eo] & STATUS_TREE_DURESS) == treeBit(tree);
  }

  /** Returns the entry's offset if it belongs to the tree and is in the given state; another tree's is not found. */
  private short checkEntry(byte tree, byte entry, byte status) {
    short e = (short) (entry & 0xFF);
    if (e >= entries) {
      ISOException.throwIt(SW_NOT_FOUND);
    }
    short eo = (short) (e * entrySize);
    if (!ownedBy(eo, tree)) {
      ISOException.throwIt(SW_NOT_FOUND);
    }
    if ((dir[eo] & STATUS_MASK) != status) {
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
