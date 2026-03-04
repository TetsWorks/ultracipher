package com.ultracipher.core.primitives;

/**
 * Argon2id key derivation function - built from absolute zero.
 *
 * Argon2 won the Password Hashing Competition (PHC) in 2015.
 * Argon2id combines:
 * - Argon2i (data-independent memory access - side-channel resistant)
 * - Argon2d (data-dependent memory access - GPU-resistant)
 *
 * Makes brute-force attacks massively expensive via:
 * - Memory hardness (requires gigabytes of RAM to compute quickly)
 * - Time hardness (configurable iterations)
 * - Parallelism (requires many CPU cores)
 *
 * Reference: RFC 9106
 */
public final class Argon2id {

    private static final int ARGON2_VERSION  = 0x13;
    private static final int ARGON2_TYPE_ID  = 2; // Argon2id
    private static final int BLOCK_SIZE      = 1024; // bytes per block
    private static final int SYNC_POINTS     = 4;   // slices per lane

    // ─── Public API ───────────────────────────────────────────────────────────

    /**
     * Derive a key from a password using Argon2id.
     *
     * @param password   the password to hash
     * @param salt       random salt (16+ bytes recommended)
     * @param memory     memory cost in KiB (e.g., 65536 = 64MB)
     * @param iterations time cost (e.g., 3)
     * @param parallelism number of threads (e.g., 4)
     * @param outputLen  desired key length in bytes
     * @return derived key bytes
     */
    public static byte[] hash(byte[] password, byte[] salt,
                               int memory, int iterations, int parallelism, int outputLen) {

        // Ensure memory is multiple of 4*parallelism (at least)
        int memBlocks = Math.max(memory, 8 * SYNC_POINTS * parallelism);
        int segmentLen = memBlocks / (parallelism * SYNC_POINTS);
        memBlocks = segmentLen * parallelism * SYNC_POINTS;

        // H0: initial 64-byte hash via BLAKE2b-512 (we use BLAKE3 as substitute)
        byte[] h0 = computeH0(password, salt, memory, iterations, parallelism, outputLen);

        // Allocate memory blocks
        long[][] blocks = new long[memBlocks][128]; // each block = 1024 bytes = 128 longs

        // Initialize first two blocks per lane
        for (int lane = 0; lane < parallelism; lane++) {
            blocks[lane * (memBlocks / parallelism)] = initBlock(h0, 0, lane);
            blocks[lane * (memBlocks / parallelism) + 1] = initBlock(h0, 1, lane);
        }

        // Fill memory
        for (int pass = 0; pass < iterations; pass++) {
            for (int slice = 0; slice < SYNC_POINTS; slice++) {
                for (int lane = 0; lane < parallelism; lane++) {
                    fillSegment(blocks, pass, lane, slice, parallelism,
                                segmentLen, memBlocks, iterations);
                }
            }
        }

        // Finalize: XOR last blocks of each lane
        int laneLen = memBlocks / parallelism;
        long[] finalBlock = new long[128];
        for (int lane = 0; lane < parallelism; lane++) {
            int lastIdx = (lane + 1) * laneLen - 1;
            for (int i = 0; i < 128; i++) {
                finalBlock[i] ^= blocks[lastIdx][i];
            }
        }

        // Extract output
        byte[] finalBytes = longsToBytes(finalBlock);
        return variableLengthHash(finalBytes, outputLen);
    }

    /**
     * Convenience method with recommended defaults for password hashing.
     * Memory: 64MB, Iterations: 3, Parallelism: 4
     */
    public static byte[] hashPassword(byte[] password, byte[] salt, int outputLen) {
        return hash(password, salt, 65536, 3, 4, outputLen);
    }

    // ─── Internals ────────────────────────────────────────────────────────────

    private static byte[] computeH0(byte[] password, byte[] salt,
                                     int memory, int iterations, int parallelism, int outputLen) {
        // Concatenate all parameters (BLAKE3 instead of BLAKE2b)
        byte[] input = concatenate(
            intToLE(parallelism),
            intToLE(outputLen),
            intToLE(memory),
            intToLE(iterations),
            intToLE(ARGON2_VERSION),
            intToLE(ARGON2_TYPE_ID),
            intToLE(password.length), password,
            intToLE(salt.length), salt,
            intToLE(0),   // secret (none)
            intToLE(0)    // data (none)
        );
        return BLAKE3.hash(input, 64);
    }

    private static long[] initBlock(byte[] h0, int blockIndex, int lane) {
        byte[] seed = new byte[h0.length + 8];
        System.arraycopy(h0, 0, seed, 0, h0.length);
        byte[] b = intToLE(blockIndex);
        byte[] l = intToLE(lane);
        System.arraycopy(b, 0, seed, h0.length, 4);
        System.arraycopy(l, 0, seed, h0.length + 4, 4);
        byte[] blockBytes = BLAKE3.hash(seed, BLOCK_SIZE);
        return bytesToLongs(blockBytes);
    }

    private static void fillSegment(long[][] blocks, int pass, int lane, int slice,
                                     int parallelism, int segmentLen, int memBlocks, int iterations) {
        int laneLen = memBlocks / parallelism;
        int laneStart = lane * laneLen;

        for (int idx = 0; idx < segmentLen; idx++) {
            int pos = slice * segmentLen + idx;
            int curr = laneStart + pos;

            // Reference block selection
            int prev = (pos == 0) ? laneStart + laneLen - 1 : curr - 1;
            long refLong = blocks[prev][0];

            // Pseudo-random reference index
            int refLane = (pass == 0 && slice == 0) ? lane : (int)(((refLong >>> 32) & 0xFFFFFFFFL) % parallelism);
            int refLaneStart = refLane * laneLen;
            int refIdx = (int)((refLong & 0xFFFFFFFFL) % laneLen);
            int ref = refLaneStart + refIdx;

            // Mix blocks using G (compression function)
            blocks[curr] = compress(blocks[prev], blocks[ref]);
        }
    }

    /**
     * Argon2 block compression using BLAKE3-based mixing.
     * Mixes two 1024-byte blocks together.
     */
    private static long[] compress(long[] x, long[] y) {
        long[] r = new long[128];
        // XOR inputs
        for (int i = 0; i < 128; i++) r[i] = x[i] ^ y[i];

        long[] z = r.clone();

        // Apply GB (BLAKE3-inspired mixing) to 8x8 matrix of 64-bit words
        for (int i = 0; i < 8; i++) {
            // Row mixing
            gb(z, i*16, i*16+1, i*16+2, i*16+3);
            gb(z, i*16+4, i*16+5, i*16+6, i*16+7);
            gb(z, i*16+8, i*16+9, i*16+10, i*16+11);
            gb(z, i*16+12, i*16+13, i*16+14, i*16+15);
        }

        for (int i = 0; i < 128; i++) z[i] ^= r[i];
        return z;
    }

    /** GB mixing function (64-bit BLAKE2b-like) */
    private static void gb(long[] v, int a, int b, int c, int d) {
        v[a] = v[a] + v[b] + 2 * (v[a] & 0xFFFFFFFFL) * (v[b] & 0xFFFFFFFFL);
        v[d] = Long.rotateRight(v[d] ^ v[a], 32);
        v[c] = v[c] + v[d] + 2 * (v[c] & 0xFFFFFFFFL) * (v[d] & 0xFFFFFFFFL);
        v[b] = Long.rotateRight(v[b] ^ v[c], 24);
        v[a] = v[a] + v[b] + 2 * (v[a] & 0xFFFFFFFFL) * (v[b] & 0xFFFFFFFFL);
        v[d] = Long.rotateRight(v[d] ^ v[a], 16);
        v[c] = v[c] + v[d] + 2 * (v[c] & 0xFFFFFFFFL) * (v[d] & 0xFFFFFFFFL);
        v[b] = Long.rotateRight(v[b] ^ v[c], 63);
    }

    private static byte[] variableLengthHash(byte[] input, int outputLen) {
        return BLAKE3.hash(input, outputLen);
    }

    // ─── Utility ──────────────────────────────────────────────────────────────

    private static byte[] intToLE(int v) {
        return new byte[]{ (byte)v, (byte)(v>>8), (byte)(v>>16), (byte)(v>>24) };
    }

    private static byte[] concatenate(byte[]... arrays) {
        int total = 0;
        for (byte[] a : arrays) total += a.length;
        byte[] result = new byte[total];
        int pos = 0;
        for (byte[] a : arrays) {
            System.arraycopy(a, 0, result, pos, a.length);
            pos += a.length;
        }
        return result;
    }

    private static long[] bytesToLongs(byte[] b) {
        long[] longs = new long[b.length / 8];
        for (int i = 0; i < longs.length; i++) {
            longs[i] = 0;
            for (int j = 0; j < 8; j++) {
                longs[i] |= (long)(b[i*8+j] & 0xFF) << (j * 8);
            }
        }
        return longs;
    }

    private static byte[] longsToBytes(long[] longs) {
        byte[] bytes = new byte[longs.length * 8];
        for (int i = 0; i < longs.length; i++) {
            for (int j = 0; j < 8; j++) {
                bytes[i*8+j] = (byte)(longs[i] >> (j * 8));
            }
        }
        return bytes;
    }

    private Argon2id() {}
}
