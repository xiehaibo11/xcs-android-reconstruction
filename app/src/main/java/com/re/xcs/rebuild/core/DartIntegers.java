package com.re.xcs.rebuild.core;

/**
 * Bounded reconstruction of native Dart 3.5.2 int conversions.
 * The original Message.toJson dispatches Mint through Object_toString, whose
 * Instance handle calls Mint::ToCString (signed 64-bit decimal). Integer's
 * toDouble calls _Double.fromInteger / Double_doubleFromInteger and
 * Smi::AsDoubleValue or Mint::AsDoubleValue. Evidence: round3/mint.
 * This class does not implement BigInt, parsing, arithmetic, or custom receivers.
 */
public final class DartIntegers {
    private DartIntegers() {}
    public static final long COMPRESSED_SMI_MIN = -(1L << 30);
    public static final long COMPRESSED_SMI_MAX = (1L << 30) - 1;

    public static boolean isInteger(Object value) {
        return value instanceof Byte || value instanceof Short ||
                value instanceof Integer || value instanceof Long;
    }

    private static long requireSigned64(Object value) {
        if (!isInteger(value)) {
            throw new IllegalArgumentException("Dart int conversion requires a signed 64-bit integral value");
        }
        return ((Number) value).longValue();
    }

    /** CID in the inspected compressed-pointer ARM64 snapshot, not every Dart ABI. */
    public static int snapshotClassId(long value) {
        return value >= COMPRESSED_SMI_MIN && value <= COMPRESSED_SMI_MAX ? 59 : 60;
    }

    public static String toDartString(Object value) {
        return Long.toString(requireSigned64(value));
    }

    /** IEEE754 conversion may round; it does not promise exact preservation above 2^53. */
    public static double toDouble(Object value) {
        return (double) requireSigned64(value);
    }
}
