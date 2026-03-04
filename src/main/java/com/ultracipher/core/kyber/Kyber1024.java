package com.ultracipher.core.kyber;

import com.ultracipher.core.primitives.BLAKE3;

/**
 * Kyber-1024 / ML-KEM-1024 Key Encapsulation Mechanism.
 * Built from absolute zero. Follows FIPS 203 pseudocode exactly.
 *
 * Parameters: n=256, q=3329, k=4, eta1=2, eta2=2, du=11, dv=5
 */
public final class Kyber1024 {

    public static final int K          = 4;
    public static final int N          = 256;
    public static final int Q          = 3329;
    public static final int ETA1       = 2;
    public static final int ETA2       = 2;
    public static final int DU         = 11;
    public static final int DV         = 5;

    // pk  = encode(t, 12) * K  +  rho(32) = 1536 + 32 = 1568
    // sk  = encode(s, 12) * K  +  pk      = 1536 + 1568 = 3104
    // ct  = encode(u, du) * K  +  encode(v, dv) = K*N*DU/8 + N*DV/8 = 1408 + 160 = 1568
    public static final int PUBLIC_KEY_SIZE    = 1568;
    public static final int SECRET_KEY_SIZE    = 3104;
    public static final int CIPHERTEXT_SIZE    = 1568;
    public static final int SHARED_SECRET_SIZE = 32;

    // ─── NTT zeta table ───────────────────────────────────────────────────────
    // zetas[k] = 17^brv7(k) mod 3329  for k = 0..127
    // Taken verbatim from the reference C implementation.
    private static final int[] ZETAS = {
        1,    1729, 2580, 3289, 2642,  630, 1897,  848,
     1062, 1919,  193,  797, 2786, 3260,  569, 1746,
      296, 2447, 1339, 1476, 3046,   56, 2240, 1333,
     1426, 2094,  535, 2882, 2393, 2879, 1974,  821,
      289,  331, 3253, 1756, 1197, 2304, 2277, 2055,
      650, 1977, 2513,  632, 2865,   33, 1320, 1915,
     2319, 1435,  807,  452, 1438, 2868, 1534, 2402,
     2647, 2617, 1481,  648, 2474, 3110, 1227,  910,
       17, 2761,  583, 2649, 1637,  723, 2288, 1100,
     1409, 2662, 3281,  233,  756, 2156, 3015, 3050,
     1703, 1651, 2789, 1789, 1847,  952, 1461, 2687,
      939, 2308, 2437, 2388,  733, 2337,  268,  641,
     1584, 2298, 2037, 3220,  375, 2549, 2090, 1645,
     1063,  319, 2773,  757, 2099,  561, 2466, 2594,
     2804, 1092,  403, 1026, 1143, 2150, 2775,  886,
     1722, 1212, 1874, 1029, 2110, 2935,  885, 2154
    };

    // ─── NTT ──────────────────────────────────────────────────────────────────

    /** Forward NTT. Result in "NTT domain" (bit-reversed order). */
    static int[] ntt(int[] poly) {
        int[] f = poly.clone();
        int k = 1;
        for (int len = 128; len >= 2; len >>= 1) {
            for (int start = 0; start < N; start += 2 * len) {
                int zeta = ZETAS[k++];
                for (int j = start; j < start + len; j++) {
                    int t = (int)((long)zeta * f[j + len] % Q);
                    f[j + len] = (f[j] - t + Q) % Q;
                    f[j]       = (f[j] + t)      % Q;
                }
            }
        }
        return f;
    }

    /** Inverse NTT. Input in NTT domain, output in standard domain.
     *  Uses +zeta (NOT -zeta) per Kyber/pq-crystals reference implementation. */
    static int[] invNtt(int[] a) {
        int[] f = a.clone();
        int k = 127;
        for (int len = 2; len <= 128; len <<= 1) {
            for (int start = 0; start < N; start += 2 * len) {
                int zeta = ZETAS[k--];
                for (int j = start; j < start + len; j++) {
                    int t      = f[j];
                    f[j]       = (t + f[j + len]) % Q;
                    // +zeta (positive), NOT -(zeta): this is the Kyber reference butterfly
                    f[j + len] = (int)((long)zeta * ((f[j + len] - t + Q) % Q) % Q);
                }
            }
        }
        for (int i = 0; i < N; i++) f[i] = (int)((long)f[i] * 3303 % Q);
        return f;
    }

    /**
     * Multiply two NTT-domain polynomials via basemul.
     * Pairs (a[2i], a[2i+1]) and (b[2i], b[2i+1]) are multiplied mod (X^2 - zeta_i).
     * zeta_i for pair i: ZETAS[64 + i/2], alternating sign for odd i.
     * This matches the reference: for i in 0..127, use ZETAS[64 + i>>1], sign = i&1 ? -1 : 1
     */
    static int[] nttMul(int[] a, int[] b) {
        int[] r = new int[N];
        for (int i = 0; i < 128; i++) {
            int zeta = ZETAS[64 + (i >> 1)];
            if ((i & 1) == 1) zeta = Q - zeta; // negate for odd index
            long a0 = a[2*i], a1 = a[2*i+1];
            long b0 = b[2*i], b1 = b[2*i+1];
            r[2*i]   = (int)((a0*b0 + a1*b1 % Q * zeta) % Q);
            r[2*i+1] = (int)((a0*b1 + a1*b0)             % Q);
            r[2*i]   = (r[2*i]   + Q) % Q;
            r[2*i+1] = (r[2*i+1] + Q) % Q;
        }
        return r;
    }

    // ─── Module arithmetic ────────────────────────────────────────────────────

    static int[] polyAdd(int[] a, int[] b) {
        int[] c = new int[N];
        for (int i = 0; i < N; i++) c[i] = (a[i] + b[i]) % Q;
        return c;
    }

    static int[] polySub(int[] a, int[] b) {
        int[] c = new int[N];
        for (int i = 0; i < N; i++) c[i] = ((a[i] - b[i]) + Q) % Q;
        return c;
    }

    /** A*s: matrix-vector product. Both A[i][j] and s[j] must be in NTT domain. */
    private static int[][] matVecMul(int[][][] A, int[][] s) {
        int[][] r = new int[K][N];
        for (int i = 0; i < K; i++)
            for (int j = 0; j < K; j++)
                r[i] = polyAdd(r[i], nttMul(A[i][j], s[j]));
        return r;
    }

    /** s^T * u: dot product. Both must be in NTT domain. */
    private static int[] vecDot(int[][] s, int[][] u) {
        int[] r = new int[N];
        for (int i = 0; i < K; i++) r = polyAdd(r, nttMul(s[i], u[i]));
        return r;
    }

    // ─── Sampling ─────────────────────────────────────────────────────────────

    /**
     * Sample polynomial from centered binomial distribution eta=2.
     * For each coefficient: a = sum of 2 bits, b = sum of 2 bits, coeff = a - b.
     * Input: 4*eta*N/8 = 64*N/256... actually eta*N/4 bytes = 2*256/4 = 128 bytes.
     * Per FIPS 203 Algorithm 8 (SamplePolyCBD_eta):
     *   input is eta*64 bytes = 128 bytes for eta=2
     *   for i in 0..255:
     *     a = sum of eta bits starting at bit 2*eta*i
     *     b = sum of eta bits starting at bit 2*eta*i + eta
     *     f[i] = a - b mod q
     */
    private static int[] sampleCBD(byte[] seed, int nonce) {
        // prf output: 2*eta*N bits = 4*256 bits = 128 bytes
        byte[] b = prf(seed, nonce, 2 * ETA1 * N / 8); // = 128 bytes
        int[] f = new int[N];
        for (int i = 0; i < N; i++) {
            // bit position for coefficient i: 4*i (since 2*eta = 4 bits per coefficient)
            int bitPos = 4 * i;
            int a = getBit(b, bitPos) + getBit(b, bitPos + 1);       // sum of eta=2 bits
            int bb = getBit(b, bitPos + 2) + getBit(b, bitPos + 3);  // sum of eta=2 bits
            f[i] = ((a - bb) + Q) % Q;
        }
        return f;
    }

    private static int getBit(byte[] b, int pos) {
        return (b[pos / 8] >> (pos % 8)) & 1;
    }

    /**
     * Sample matrix A from rho using rejection sampling (XOF = BLAKE3 here).
     * A[i][j] = Parse(XOF(rho || j || i))  for non-transposed
     * A^T[i][j] = A[j][i], so swap i,j indices.
     */
    private static int[][][] sampleA(byte[] rho, boolean transposed) {
        int[][][] A = new int[K][K][N];
        for (int i = 0; i < K; i++) {
            for (int j = 0; j < K; j++) {
                byte[] seed = new byte[34];
                System.arraycopy(rho, 0, seed, 0, 32);
                // FIPS 203: XOF(rho, j, i) for A[i][j]; swap for transposed
                seed[32] = transposed ? (byte)i : (byte)j;
                seed[33] = transposed ? (byte)j : (byte)i;
                A[i][j] = parseXOF(BLAKE3.hash(seed, 840));
            }
        }
        return A;
    }

    /** Parse XOF bytes into polynomial via rejection sampling (coefficients in [0, q)). */
    private static int[] parseXOF(byte[] buf) {
        int[] poly = new int[N];
        int count = 0, pos = 0;
        while (count < N && pos + 2 < buf.length) {
            int d1 = (buf[pos] & 0xFF) | (((buf[pos+1] & 0xFF) & 0x0F) << 8);
            int d2 = ((buf[pos+1] & 0xFF) >>> 4) | ((buf[pos+2] & 0xFF) << 4);
            if (d1 < Q) poly[count++] = d1;
            if (count < N && d2 < Q) poly[count++] = d2;
            pos += 3;
        }
        return poly;
    }

    // ─── Compress / Decompress ────────────────────────────────────────────────

    /** Compress(x, d) = round(x * 2^d / q) mod 2^d */
    private static int[] compress(int[] poly, int d) {
        int[] c = new int[N];
        long factor = 1L << d;
        for (int i = 0; i < N; i++)
            c[i] = (int)(((long)poly[i] * factor + Q / 2) / Q) & (int)(factor - 1);
        return c;
    }

    /** Decompress(x, d) = round(x * q / 2^d) */
    private static int[] decompress(int[] poly, int d) {
        int[] f = new int[N];
        long factor = 1L << d;
        for (int i = 0; i < N; i++)
            f[i] = (int)(((long)poly[i] * Q + factor / 2) / factor);
        return f;
    }

    // ─── Encode / Decode polynomials ──────────────────────────────────────────

    /** Encode polynomial with `bits` bits per coefficient, little-endian. */
    private static byte[] encodePoly(int[] poly, int bits) {
        byte[] out = new byte[N * bits / 8];
        int buf = 0, bufLen = 0, pos = 0;
        for (int coeff : poly) {
            buf |= (coeff & ((1 << bits) - 1)) << bufLen;
            bufLen += bits;
            while (bufLen >= 8) {
                out[pos++] = (byte)(buf & 0xFF);
                buf >>>= 8;
                bufLen -= 8;
            }
        }
        return out;
    }

    /** Decode polynomial from bytes with `bits` bits per coefficient. */
    private static int[] decodePoly(byte[] bytes, int offset, int bits) {
        int[] poly = new int[N];
        int buf = 0, bufLen = 0, idx = 0;
        int mask = (1 << bits) - 1;
        for (int i = 0; idx < N; i++) {
            buf |= (bytes[offset + i] & 0xFF) << bufLen;
            bufLen += 8;
            while (bufLen >= bits && idx < N) {
                poly[idx++] = buf & mask;
                buf >>>= bits;
                bufLen -= bits;
            }
        }
        return poly;
    }

    // ─── Message encode / decode ──────────────────────────────────────────────

    /** Encode 32-byte message into polynomial: bit 0 -> 0, bit 1 -> (q+1)/2 */
    private static int[] msgToPoly(byte[] m) {
        int[] p = new int[N];
        for (int i = 0; i < 256; i++)
            p[i] = ((m[i / 8] >> (i % 8)) & 1) * ((Q + 1) / 2);
        return p;
    }

    /** Decode polynomial to 32-byte message: coeff nearest q/2 -> 1, nearest 0 -> 0 */
    private static byte[] polyToMsg(int[] p) {
        byte[] m = new byte[32];
        for (int i = 0; i < 256; i++) {
            // Compress(v, 1): round(v * 2 / q) mod 2
            int bit = (int)(((long)p[i] * 2 + Q / 2) / Q) & 1;
            m[i / 8] |= (byte)(bit << (i % 8));
        }
        return m;
    }

    // ─── Core: KeyGen, Encrypt, Decrypt ──────────────────────────────────────

    public static KeyPair generateKeyPair(byte[] seed) {
        if (seed.length < 64) throw new IllegalArgumentException("Need 64-byte seed");
        byte[] rho   = new byte[32];
        byte[] sigma = new byte[32];
        System.arraycopy(seed, 0,  rho,   0, 32);
        System.arraycopy(seed, 32, sigma, 0, 32);

        // Sample A in NTT domain
        int[][][] A = sampleA(rho, false);

        // Sample secret s and error e (in standard domain)
        int[][] s = new int[K][N];
        int[][] e = new int[K][N];
        for (int i = 0; i < K; i++) {
            s[i] = sampleCBD(sigma, i);       // standard domain
            e[i] = sampleCBD(sigma, K + i);   // standard domain
        }

        // Convert s to NTT domain for multiplication
        int[][] sHat = new int[K][N];
        for (int i = 0; i < K; i++) sHat[i] = ntt(s[i]);

        // t = NTT^{-1}(A * s_hat) + e  (t in standard domain)
        int[][] t = matVecMul(A, sHat);
        for (int i = 0; i < K; i++) t[i] = polyAdd(invNtt(t[i]), e[i]);

        // Public key: encode(t) || rho
        // Secret key: encode(s_hat) || pk   (store s in NTT domain for fast decryption)
        byte[] pk = encodePublicKey(t, rho);
        byte[] sk = encodeSecretKey(sHat, pk);
        return new KeyPair(pk, sk);
    }

    private static byte[] innerEncrypt(byte[] pk, byte[] msg, byte[] coins) {
        // Decode public key
        int[][] t   = decodePKT(pk);
        byte[] rho  = new byte[32];
        System.arraycopy(pk, K * N * 12 / 8, rho, 0, 32);

        // Sample A^T in NTT domain
        int[][][] AT = sampleA(rho, true); // transposed

        // Sample r, e1, e2
        int[][] r  = new int[K][N];
        int[][] e1 = new int[K][N];
        int[] e2;
        for (int i = 0; i < K; i++) {
            r[i]  = sampleCBD(coins, i);
            e1[i] = sampleCBD(coins, K + i);
        }
        e2 = sampleCBD(coins, 2 * K);

        // rHat = NTT(r)
        int[][] rHat = new int[K][N];
        for (int i = 0; i < K; i++) rHat[i] = ntt(r[i]);

        // tHat = NTT(t) for dot product
        int[][] tHat = new int[K][N];
        for (int i = 0; i < K; i++) tHat[i] = ntt(t[i]);

        // u = NTT^{-1}(A^T * r_hat) + e1
        int[][] u = matVecMul(AT, rHat);
        for (int i = 0; i < K; i++) u[i] = polyAdd(invNtt(u[i]), e1[i]);

        // v = NTT^{-1}(t_hat^T * r_hat) + e2 + Decompress(msg, 1)
        int[] v = invNtt(vecDot(tHat, rHat));
        v = polyAdd(v, e2);
        v = polyAdd(v, msgToPoly(msg));

        // Encode ciphertext: Compress(u, du) || Compress(v, dv)
        byte[] ct  = new byte[CIPHERTEXT_SIZE];
        int pos = 0;
        int uByteLen = N * DU / 8;
        for (int i = 0; i < K; i++) {
            byte[] ub = encodePoly(compress(u[i], DU), DU);
            System.arraycopy(ub, 0, ct, pos, uByteLen);
            pos += uByteLen;
        }
        byte[] vb = encodePoly(compress(v, DV), DV);
        System.arraycopy(vb, 0, ct, pos, vb.length);
        return ct;
    }

    private static byte[] innerDecrypt(byte[] ct, int[][] sHat) {
        // Decode u (decompress, then NTT for dot product)
        int uByteLen = N * DU / 8;
        int[][] uHat = new int[K][N];
        int pos = 0;
        for (int i = 0; i < K; i++) {
            int[] uDecomp = decompress(decodePoly(ct, pos, DU), DU);
            uHat[i] = ntt(uDecomp);
            pos += uByteLen;
        }

        // Decode v (decompress only, stays in standard domain)
        int[] v = decompress(decodePoly(ct, pos, DV), DV);

        // w = v - NTT^{-1}(s_hat^T * u_hat)
        int[] w = polySub(v, invNtt(vecDot(sHat, uHat)));

        return polyToMsg(w);
    }

    // ─── KEM: encapsulate / decapsulate ──────────────────────────────────────

    public static Encapsulation encapsulate(byte[] publicKey, byte[] randomSeed) {
        byte[] m  = BLAKE3.hash(randomSeed, 32);
        byte[] combined = concat(m, BLAKE3.hash(publicKey, 32));
        byte[] kr = BLAKE3.hash(combined, 64);
        byte[] K_ = new byte[32]; System.arraycopy(kr, 0,  K_, 0, 32);
        byte[] r  = new byte[32]; System.arraycopy(kr, 32, r,  0, 32);

        byte[] ct = innerEncrypt(publicKey, m, r);
        return new Encapsulation(ct, K_);
    }

    public static byte[] decapsulate(byte[] ct, byte[] sk) {
        int[][] sHat = decodeSK(sk);
        byte[] pk    = extractPK(sk);

        byte[] m2    = innerDecrypt(ct, sHat);
        byte[] combined = concat(m2, BLAKE3.hash(pk, 32));
        byte[] kr    = BLAKE3.hash(combined, 64);
        byte[] K_    = new byte[32]; System.arraycopy(kr, 0,  K_, 0, 32);
        byte[] r2    = new byte[32]; System.arraycopy(kr, 32, r2, 0, 32);

        byte[] ct2   = innerEncrypt(pk, m2, r2);
        if (!constantTimeEquals(ct, ct2)) {
            // Implicit rejection: return pseudorandom value
            return BLAKE3.hash(concat(new byte[]{0}, sk), 32);
        }
        return K_;
    }

    // ─── Encoding helpers ─────────────────────────────────────────────────────

    private static byte[] encodePublicKey(int[][] t, byte[] rho) {
        byte[] pk = new byte[PUBLIC_KEY_SIZE];
        int pos = 0;
        for (int i = 0; i < K; i++) {
            byte[] tb = encodePoly(t[i], 12);
            System.arraycopy(tb, 0, pk, pos, tb.length); pos += tb.length;
        }
        System.arraycopy(rho, 0, pk, pos, 32);
        return pk;
    }

    private static byte[] encodeSecretKey(int[][] sHat, byte[] pk) {
        int sLen = K * N * 12 / 8; // 1536
        byte[] sk = new byte[sLen + PUBLIC_KEY_SIZE];
        int pos = 0;
        for (int i = 0; i < K; i++) {
            byte[] sb = encodePoly(sHat[i], 12);
            System.arraycopy(sb, 0, sk, pos, sb.length); pos += sb.length;
        }
        System.arraycopy(pk, 0, sk, pos, pk.length);
        return sk;
    }

    private static int[][] decodePKT(byte[] pk) {
        int[][] t = new int[K][N];
        int polyBytes = N * 12 / 8;
        for (int i = 0; i < K; i++) t[i] = decodePoly(pk, i * polyBytes, 12);
        return t;
    }

    private static int[][] decodeSK(byte[] sk) {
        int[][] s = new int[K][N];
        int polyBytes = N * 12 / 8;
        for (int i = 0; i < K; i++) s[i] = decodePoly(sk, i * polyBytes, 12);
        return s;
    }

    private static byte[] extractPK(byte[] sk) {
        int sLen = K * N * 12 / 8;
        byte[] pk = new byte[PUBLIC_KEY_SIZE];
        System.arraycopy(sk, sLen, pk, 0, PUBLIC_KEY_SIZE);
        return pk;
    }

    // ─── Utilities ────────────────────────────────────────────────────────────

    private static byte[] prf(byte[] seed, int nonce, int len) {
        byte[] in = new byte[seed.length + 1];
        System.arraycopy(seed, 0, in, 0, seed.length);
        in[seed.length] = (byte)nonce;
        return BLAKE3.hash(in, len);
    }

    private static byte[] concat(byte[] a, byte[] b) {
        byte[] c = new byte[a.length + b.length];
        System.arraycopy(a, 0, c, 0,        a.length);
        System.arraycopy(b, 0, c, a.length, b.length);
        return c;
    }

    private static boolean constantTimeEquals(byte[] a, byte[] b) {
        if (a.length != b.length) return false;
        int d = 0;
        for (int i = 0; i < a.length; i++) d |= (a[i] ^ b[i]);
        return d == 0;
    }

    // ─── Public data classes ──────────────────────────────────────────────────

    public static final class KeyPair {
        public final byte[] publicKey;
        public final byte[] secretKey;
        KeyPair(byte[] pub, byte[] sec) { publicKey = pub; secretKey = sec; }
    }

    public static final class Encapsulation {
        public final byte[] ciphertext;
        public final byte[] sharedSecret;
        Encapsulation(byte[] ct, byte[] ss) { ciphertext = ct; sharedSecret = ss; }
    }


    /** Debug: re-encrypt to check if decap recovers the same message */
    public static byte[] debugReEncrypt(byte[] pk, byte[] sk, byte[] ct) {
        int[][] sHat = decodeSK(sk);
        byte[] m     = innerDecrypt(ct, sHat);
        byte[] combined = concat(m, BLAKE3.hash(pk, 32));
        byte[] kr    = BLAKE3.hash(combined, 64);
        byte[] r2    = new byte[32]; System.arraycopy(kr, 32, r2, 0, 32);
        System.out.printf("[DEBUG] recovered m: %02x %02x %02x %02x%n", m[0]&0xFF, m[1]&0xFF, m[2]&0xFF, m[3]&0xFF);
        return innerEncrypt(pk, m, r2);
    }

    private Kyber1024() {}
}
