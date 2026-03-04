package com.ultracipher.core.math;

/**
 * Galois Field GF(2^8) arithmetic - built from absolute zero.
 * Irreducible polynomial: x^8 + x^4 + x^3 + x + 1 (0x11B) - the AES polynomial.
 *
 * Every operation here is pure bit manipulation. No libraries. No shortcuts.
 */
public final class GaloisField {

    // AES irreducible polynomial: x^8 + x^4 + x^3 + x + 1
    private static final int IRREDUCIBLE_POLY = 0x11B;

    // Precomputed log and exp tables for fast multiplication
    private static final int[] EXP_TABLE = new int[512];
    private static final int[] LOG_TABLE = new int[256];

    static {
        buildLogExpTables();
    }

    private static void buildLogExpTables() {
        // Generator 3 = 0x03 is a primitive root of GF(2^8) with poly 0x11B.
        // Using xtime(x) alone (generator 2) does NOT cycle through all 255 elements.
        int x = 1;
        for (int i = 0; i < 255; i++) {
            EXP_TABLE[i] = x;
            LOG_TABLE[x] = i;
            // Multiply by generator 3 = (2 XOR 1) in GF(2^8)
            x = xtime(x) ^ x;
        }
        // Duplicate for wraparound so (a+b) % 255 never needs bounds check
        for (int i = 255; i < 512; i++) {
            EXP_TABLE[i] = EXP_TABLE[i - 255];
        }
        LOG_TABLE[0] = 0; // undefined, but set to 0 for safety
    }

    /**
     * Multiply by 2 in GF(2^8) - the fundamental xtime operation.
     * Left shift by 1, XOR with irreducible poly if high bit was set.
     */
    public static int xtime(int a) {
        int result = (a << 1) & 0xFF;
        if ((a & 0x80) != 0) {
            result ^= 0x1B; // low 8 bits of irreducible poly
        }
        return result;
    }

    /**
     * Full GF(2^8) multiplication using precomputed log/exp tables.
     * Time complexity: O(1)
     */
    public static int multiply(int a, int b) {
        if (a == 0 || b == 0) return 0;
        return EXP_TABLE[(LOG_TABLE[a & 0xFF] + LOG_TABLE[b & 0xFF]) % 255];
    }

    /**
     * GF(2^8) multiplication via Russian peasant algorithm (no tables needed).
     * Used during table initialization and as fallback.
     */
    public static int multiplyNaive(int a, int b) {
        int result = 0;
        int aa = a & 0xFF;
        int bb = b & 0xFF;
        while (bb != 0) {
            if ((bb & 1) != 0) {
                result ^= aa;
            }
            aa = xtime(aa);
            bb >>= 1;
        }
        return result & 0xFF;
    }

    /**
     * GF(2^8) inverse via extended Euclidean algorithm.
     * Used to build AES S-box.
     */
    public static int inverse(int a) {
        if (a == 0) return 0;
        return EXP_TABLE[255 - LOG_TABLE[a & 0xFF]];
    }

    /**
     * GF(2^8) power: a^n
     */
    public static int power(int a, int n) {
        if (a == 0) return 0;
        if (n == 0) return 1;
        return EXP_TABLE[(LOG_TABLE[a & 0xFF] * n) % 255];
    }

    /**
     * Dot product of two byte vectors in GF(2^8).
     */
    public static int dotProduct(int[] a, int[] b) {
        int result = 0;
        for (int i = 0; i < a.length; i++) {
            result ^= multiply(a[i] & 0xFF, b[i] & 0xFF);
        }
        return result;
    }

    /**
     * Matrix-vector multiplication in GF(2^8).
     * Used by AES MixColumns.
     */
    public static int[] matrixVectorMultiply(int[][] matrix, int[] vector) {
        int[] result = new int[matrix.length];
        for (int i = 0; i < matrix.length; i++) {
            result[i] = dotProduct(matrix[i], vector);
        }
        return result;
    }

    private GaloisField() {}
}
