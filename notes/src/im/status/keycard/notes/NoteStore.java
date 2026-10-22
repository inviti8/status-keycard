package im.status.keycard.notes;

import javacard.framework.Shareable;

/**
 * The note store's interface to the Keycard applet (docs/NOTE_STORE.md). This interface is frozen: the
 * store package outlives Keycard applet reinstalls, and a changed interface means a reinstalled store, which
 * loses every note.
 *
 * All arrays passed in are the APDU buffer (a global array, so it crosses the applet firewall). Access control
 * (secure channel, PIN) is the caller's job; the store only hands this interface to the Keycard applet.
 *
 * Every per-note call takes the tree of the active PIN: 0 for the main PIN, 1 for the duress PIN. A tree sees and
 * changes only its own notes; the other tree's notes behave as if absent (not found, not counted, tags not
 * compared).
 */
public interface NoteStore extends Shareable {
  /**
   * Writes {@code version:1 blocksTotal:2 blocksFree:2 entriesTotal:1 entriesFree:1 metaLen:1} at off, as seen
   * from the tree: the other tree's notes are taken out of the totals, so an empty tree shows free == total.
   *
   * @param scratchOff start of scratch space in buf for the free-block bitmap (blocks/8 bytes)
   * @return the number of bytes written (8)
   */
  short status(byte tree, byte[] buf, short off, short scratchOff);

  /**
   * Writes as many of the tree's entries {@code [entry:1 status:1 len:2 tag:32 meta:M]} as fit in maxLen - 1
   * bytes, starting at entry index first, followed by the next index to list or 0xFF.
   *
   * @return the number of bytes written
   */
  short list(byte tree, byte first, byte[] buf, short off, short maxLen);

  /**
   * Reserves blocks and an entry in state WRITING for a note of {@code len:2 tag:32 meta:M} read at dataOff.
   * The tag must be unique within the tree.
   *
   * @param scratchOff start of scratch space in buf, past the command data
   * @return the entry index
   */
  byte begin(byte tree, byte[] buf, short dataOff, short scratchOff);

  /** Copies len bytes at off into a WRITING entry's note at the given offset. */
  void write(byte tree, byte entry, short offset, byte[] buf, short off, short len);

  /**
   * Copies up to len bytes of the note from the given offset to buf at off.
   *
   * @param held true to require a HELD entry, false to require a WRITING one
   * @return the number of bytes copied
   */
  short read(byte tree, byte entry, boolean held, short offset, byte[] buf, short off, short len);

  /** Length of an entry's note; held selects the required state as in read(). */
  short length(byte tree, byte entry, boolean held);

  /** Flips a WRITING entry to HELD. The caller has verified the note's hash. */
  void commit(byte tree, byte entry);

  /** Frees a HELD entry, or a WRITING one if abort is true. The 32-byte tag at tagOff must match. */
  void delete(byte tree, byte entry, boolean abort, byte[] buf, short tagOff);

  /** Replaces a HELD entry's meta with the M bytes after the 32-byte tag at tagOff, which must match. */
  void setMeta(byte tree, byte entry, byte[] buf, short tagOff);

  /** Makes every entry of both trees dead at once (factory reset). One atomic write. */
  void wipe();

  /** The meta length M fixed at install. */
  byte metaLength();
}
