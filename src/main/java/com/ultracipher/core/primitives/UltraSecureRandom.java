package com.ultracipher.core.primitives;

/**
 * Cryptographically secure random number generator - built from absolute zero.
 *
 * Uses a ChaCha20-based CSPRNG seeded from system entropy sources:
 * - System nanoseconds (high-resolution timer)
 * - Thread ID
 * - Object hash codes (heap addresses, JVM state)
 * - Memory statistics
 *
 * The seed is mixed through BLAKE3 before use.
 *
 * For production use, seed with OS entropy (/dev/urandom) if available.
 */
public final class UltraSecureRandom {

    private final int[] key;    // 256-bit ChaCha20 key
    private final int[] nonce;  // 96-bit nonce
    private int counter;        // block counter
    private byte[] buffer;      // keystream buffer
    private int bufferPos;

    public UltraSecureRandom() {
        this(gatherEntropy());
    }

    public UltraSecureRandom(byte[] seed) {
        byte[] keyBytes = BLAKE3.deriveKey("UltraSecureRandom.key v1", seed, 32);
        byte[] nonceBytes = BLAKE3.deriveKey("UltraSecureRandom.nonce v1", seed, 12);

        key = new int[8];
        for (int i = 0; i < 8; i++) {
            key[i] = (keyBytes[i*4] & 0xFF)
                   | ((keyBytes[i*4+1] & 0xFF) << 8)
                   | ((keyBytes[i*4+2] & 0xFF) << 16)
                   | ((keyBytes[i*4+3] & 0xFF) << 24);
        }

        nonce = new int[3];
        for (int i = 0; i < 3; i++) {
            nonce[i] = (nonceBytes[i*4] & 0xFF)
                     | ((nonceBytes[i*4+1] & 0xFF) << 8)
                     | ((nonceBytes[i*4+2] & 0xFF) << 16)
                     | ((nonceBytes[i*4+3] & 0xFF) << 24);
        }

        counter = 0;
        buffer = new byte[0];
        bufferPos = 0;
    }

    /**
     * Fill array with cryptographically secure random bytes.
     */
    public synchronized void nextBytes(byte[] out) {
        nextBytes(out, 0, out.length);
    }

    public synchronized void nextBytes(byte[] out, int offset, int length) {
        int produced = 0;
        while (produced < length) {
            if (bufferPos >= buffer.length) {
                refillBuffer();
            }
            int toCopy = Math.min(buffer.length - bufferPos, length - produced);
            System.arraycopy(buffer, bufferPos, out, offset + produced, toCopy);
            bufferPos += toCopy;
            produced += toCopy;
        }
    }

    private void refillBuffer() {
        // Generate fresh ChaCha20 block as keystream
        buffer = generateChaChaBlock(key, counter++, nonce);
        bufferPos = 0;

        // Reseed periodically to provide forward secrecy (every 256 blocks)
        if (counter % 256 == 0) {
            reseed();
        }
    }

    private void reseed() {
        // Mix current key with fresh entropy
        byte[] newEntropy = gatherEntropy();
        byte[] combined = new byte[32 + newEntropy.length];
        // Current key bytes
        for (int i = 0; i < 8; i++) {
            combined[i*4]   = (byte) key[i];
            combined[i*4+1] = (byte)(key[i] >> 8);
            combined[i*4+2] = (byte)(key[i] >> 16);
            combined[i*4+3] = (byte)(key[i] >> 24);
        }
        System.arraycopy(newEntropy, 0, combined, 32, newEntropy.length);
        byte[] newKey = BLAKE3.hash(combined, 32);
        for (int i = 0; i < 8; i++) {
            key[i] = (newKey[i*4] & 0xFF)
                   | ((newKey[i*4+1] & 0xFF) << 8)
                   | ((newKey[i*4+2] & 0xFF) << 16)
                   | ((newKey[i*4+3] & 0xFF) << 24);
        }
    }

    public int nextInt() {
        byte[] b = new byte[4];
        nextBytes(b);
        return (b[0] & 0xFF) | ((b[1] & 0xFF) << 8) | ((b[2] & 0xFF) << 16) | ((b[3] & 0xFF) << 24);
    }

    public int nextInt(int bound) {
        if (bound <= 0) throw new IllegalArgumentException("Bound must be positive");
        int bits, val;
        do {
            bits = nextInt() >>> 1;
            val  = bits % bound;
        } while (bits - val + (bound - 1) < 0);
        return val;
    }

    public long nextLong() {
        byte[] b = new byte[8];
        nextBytes(b);
        long v = 0;
        for (int i = 0; i < 8; i++) v |= ((long)(b[i] & 0xFF)) << (i * 8);
        return v;
    }

    public byte[] randomBytes(int n) {
        byte[] b = new byte[n];
        nextBytes(b);
        return b;
    }

    // ─── Entropy Gathering ────────────────────────────────────────────────────

    /**
     * Gather entropy from multiple independent sources.
     * The more sources, the more entropy even if individual sources are weak.
     */
    private static byte[] gatherEntropy() {
        long t1 = System.nanoTime();
        long t2 = System.currentTimeMillis();
        long t3 = Runtime.getRuntime().freeMemory();
        long t4 = Runtime.getRuntime().totalMemory();
        long t5 = Thread.currentThread().getId();
        long t6 = System.identityHashCode(new Object());
        long t7 = System.identityHashCode(Thread.currentThread());
        long t8 = System.nanoTime(); // Second reading - differs from t1

        byte[] entropy = new byte[64];
        writeLong(entropy, 0,  t1);
        writeLong(entropy, 8,  t2);
        writeLong(entropy, 16, t3);
        writeLong(entropy, 24, t4);
        writeLong(entropy, 32, t5);
        writeLong(entropy, 40, t6);
        writeLong(entropy, 48, t7);
        writeLong(entropy, 56, t8);

        return BLAKE3.hash(entropy, 64);
    }

    private static void writeLong(byte[] b, int off, long v) {
        for (int i = 0; i < 8; i++) b[off + i] = (byte)(v >> (i * 8));
    }

    // ─── ChaCha20 Block ───────────────────────────────────────────────────────

    private static final int[] SIGMA = {
        0x61707865, 0x3320646E, 0x79622D32, 0x6B206574
    };

    private static byte[] generateChaChaBlock(int[] key, int counter, int[] nonce) {
        int[] state = new int[16];
        state[0]  = SIGMA[0]; state[1]  = SIGMA[1]; state[2]  = SIGMA[2]; state[3]  = SIGMA[3];
        for (int i = 0; i < 8; i++) state[4 + i] = key[i];
        state[12] = counter;
        state[13] = nonce[0]; state[14] = nonce[1]; state[15] = nonce[2];

        int[] working = state.clone();

        for (int i = 0; i < 10; i++) {
            qr(working, 0, 4,  8, 12); qr(working, 1, 5,  9, 13);
            qr(working, 2, 6, 10, 14); qr(working, 3, 7, 11, 15);
            qr(working, 0, 5, 10, 15); qr(working, 1, 6, 11, 12);
            qr(working, 2, 7,  8, 13); qr(working, 3, 4,  9, 14);
        }

        for (int i = 0; i < 16; i++) working[i] += state[i];

        byte[] block = new byte[64];
        for (int i = 0; i < 16; i++) {
            block[i*4]   = (byte)  working[i];
            block[i*4+1] = (byte) (working[i] >> 8);
            block[i*4+2] = (byte) (working[i] >> 16);
            block[i*4+3] = (byte) (working[i] >> 24);
        }
        return block;
    }

    private static void qr(int[] s, int a, int b, int c, int d) {
        s[a]+=s[b]; s[d]^=s[a]; s[d]=Integer.rotateLeft(s[d],16);
        s[c]+=s[d]; s[b]^=s[c]; s[b]=Integer.rotateLeft(s[b],12);
        s[a]+=s[b]; s[d]^=s[a]; s[d]=Integer.rotateLeft(s[d], 8);
        s[c]+=s[d]; s[b]^=s[c]; s[b]=Integer.rotateLeft(s[b], 7);
    }

    private UltraSecureRandom(UltraSecureRandom other) { throw new UnsupportedOperationException(); }
}
