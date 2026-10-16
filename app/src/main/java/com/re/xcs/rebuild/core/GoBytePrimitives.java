package com.re.xcs.rebuild.core;

/**
 * Executable semantic reconstruction of Go countbytebody (ELF 0x5ae90) and
 * indexbytebody (0x5b310), not recovered authoring source or a JNI replacement.
 * All positions are byte positions. indexOf returns an offset relative to the
 * requested slice. Java accesses stay inside that slice; the original ARM64
 * index routine reads entire aligned 32-byte blocks and masks outside bytes.
 * No RSA or other business call site has been established for these helpers.
 */
public final class GoBytePrimitives {
    private GoBytePrimitives() {}

    /** Count occurrences of target's unsigned byte representation. */
    public static int count(byte[] data, int offset, int length, byte target) {
        checkSlice(data, offset, length);
        int count = 0;
        for (int i = offset, end = offset + length; i < end; i++) {
            if (data[i] == target) count++;
        }
        return count;
    }

    /** Return the first matching byte's slice-relative index, or -1. */
    public static int indexOf(byte[] data, int offset, int length, byte target) {
        checkSlice(data, offset, length);
        for (int i = offset, end = offset + length; i < end; i++) {
            if (data[i] == target) return i - offset;
        }
        return -1;
    }

    /** Convenience overload accepting an explicitly unsigned byte in [0,255]. */
    public static int count(byte[] data, int offset, int length, int target) {
        checkTarget(target);
        return count(data, offset, length, (byte) target);
    }

    /** Convenience overload accepting an explicitly unsigned byte in [0,255]. */
    public static int indexOf(byte[] data, int offset, int length, int target) {
        checkTarget(target);
        return indexOf(data, offset, length, (byte) target);
    }

    private static void checkTarget(int target) {
        if (target < 0 || target > 255) {
            throw new IllegalArgumentException("target must be an unsigned byte");
        }
    }

    private static void checkSlice(byte[] data, int offset, int length) {
        // A null, empty slice models a Go nil slice. Other null uses are invalid.
        if (data == null) {
            if (offset == 0 && length == 0) return;
            throw new NullPointerException("nonempty or displaced null slice");
        }
        // Subtraction avoids an offset+length overflow during validation.
        if (offset < 0 || length < 0 || offset > data.length
                || length > data.length - offset) {
            throw new IndexOutOfBoundsException("slice outside byte array");
        }
    }
}
