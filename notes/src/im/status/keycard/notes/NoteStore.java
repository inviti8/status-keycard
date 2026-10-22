package im.status.keycard.notes;

import javacard.framework.Shareable;

/**
 * The note store's interface to the Keycard applet (docs/NOTE_STORE.md). This interface is frozen: the
 * store package outlives Keycard applet reinstalls, and a changed interface means a reinstalled store, which
 * loses every note.
 *
 * All arrays passed in are the APDU buffer (a global array, so it crosses the applet firewall). Access control
 * (secure channel, PIN) is the caller's job; the store only hands this interface to the Keycard package.
 */
public interface NoteStore extends Shareable {
  /**
   * Writes {@code version:1 blocksTotal:2 blocksFree:2 entriesTotal:1 entriesFree:1 metaLen:1} at off.
   *
   * @param scratchOff start of scratch space in buf for the free-block bitmap (blocks/8 bytes)
   * @return the number of bytes written (8)
   */
  short status(byte[] buf, short off, short scratchOff);

  /**
   * Writes as many live entries {@code [entry:1 status:1 len:2 tag:32 meta:M]} as fit in maxLen - 1 bytes,
   * starting at entry index first, followed by the next index to list or 0xFF.
   *
   * @return the number of bytes written
   */
  short list(byte first, byte[] buf, short off, short maxLen);

  /**
   * Reserves blocks and an entry in state WRITING for a note of {@code len:2 tag:32 meta:M} read at dataOff.
   *
   * @param scratchOff start of scratch space in buf, past the command data
   * @return the entry index
   */
  byte begin(byte[] buf, short dataOff, short scratchOff);

  /** Copies len bytes at off into a WRITING entry's note at the given offset. */
  void write(byte entry, short offset, byte[] buf, short off, short len);

  /**
   * Copies up to len bytes of the note from the given offset to buf at off.
   *
   * @param held true to require a HELD entry, false to require a WRITING one
   * @return the number of bytes copied
   */
  short read(byte entry, boolean held, short offset, byte[] buf, short off, short len);

  /** Length of a live entry's note; held selects the required state as in read(). */
  short length(byte entry, boolean held);

  /** Flips a WRITING entry to HELD. The caller has verified the note's hash. */
  void commit(byte entry);

  /** Frees a HELD entry, or a WRITING one if abort is true. The 32-byte tag at tagOff must match. */
  void delete(byte entry, boolean abort, byte[] buf, short tagOff);

  /** Replaces a HELD entry's meta with the M bytes after the 32-byte tag at tagOff, which must match. */
  void setMeta(byte entry, byte[] buf, short tagOff);

  /** Makes every entry dead at once (duress PIN, factory reset). One atomic write. */
  void wipe();

  /** The meta length M fixed at install. */
  byte metaLength();
}
