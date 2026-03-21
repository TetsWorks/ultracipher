package com.ultracipher;

import com.ultracipher.core.modes.AES256GCM;
import com.ultracipher.core.primitives.*;
import com.ultracipher.core.kyber.Kyber1024;

import java.util.Arrays;

/**
 * Statistically rigorous benchmark.
 *
 * Methodology:
 * - 3 warmup runs (JIT compilation, branch predictor, cache fill)
 * - 7 measurement runs
 * - Reports: min, max, mean, stddev, coefficient of variation
 * - Separate benchmarks per algorithm, no interleaving
 * - Forces GC before each algorithm suite to equalize GC pressure
 */
public final class Benchmark {

    private static final int WARMUP = 3;
    private static final int RUNS   = 7;
    private static final UltraSecureRandom RNG = new UltraSecureRandom();

    public static void main(String[] args) {
        System.out.println("╔══════════════════════════════════════════════════════════════╗");
        System.out.println("║         UltraCipher — Statistical Performance Benchmark       ║");
        System.out.println("╚══════════════════════════════════════════════════════════════╝");
        System.out.printf("  Warmup runs: %d  |  Measurement runs: %d%n%n", WARMUP, RUNS);

        benchAES();
        benchChaCha();
        benchBLAKE3();
        benchKyber();
    }

    // ─── AES-256-GCM ──────────────────────────────────────────────────────────

    static void benchAES() {
        System.out.println("┌─────────────────────────────────────────────────────────────┐");
        System.out.println("│  AES-256-GCM                                                │");
        System.out.println("└─────────────────────────────────────────────────────────────┘");
        byte[] key   = RNG.randomBytes(32);
        byte[] nonce = RNG.randomBytes(12);
        byte[] aad   = RNG.randomBytes(16);

        int[] sizes = {1024, 16*1024, 64*1024, 1024*1024};
        for (int size : sizes) {
            byte[] pt = RNG.randomBytes(size);
            gc();

            double[] mb = new double[RUNS];
            // Warmup
            for (int i = 0; i < WARMUP; i++) {
                AES256GCM.encrypt(pt, aad, key, nonce);
            }
            // Measure
            for (int i = 0; i < RUNS; i++) {
                long t0 = System.nanoTime();
                byte[] ct = AES256GCM.encrypt(pt, aad, key, nonce);
                AES256GCM.decrypt(ct, aad, key, nonce);
                long ns = System.nanoTime() - t0;
                mb[i] = (size * 2.0) / (ns / 1e9) / (1024*1024);
            }
            printStats("  " + fmtSize(size), mb, "MB/s");
        }
        System.out.println();
    }

    // ─── ChaCha20-Poly1305 ────────────────────────────────────────────────────

    static void benchChaCha() {
        System.out.println("┌─────────────────────────────────────────────────────────────┐");
        System.out.println("│  ChaCha20-Poly1305                                          │");
        System.out.println("└─────────────────────────────────────────────────────────────┘");
        byte[] key   = RNG.randomBytes(32);
        byte[] nonce = RNG.randomBytes(12);

        int[] sizes = {1024, 16*1024, 64*1024, 1024*1024};
        for (int size : sizes) {
            byte[] pt = RNG.randomBytes(size);
            gc();

            double[] mb = new double[RUNS];
            for (int i = 0; i < WARMUP; i++) ChaCha20Poly1305.encrypt(pt, null, key, nonce);
            for (int i = 0; i < RUNS; i++) {
                long t0 = System.nanoTime();
                byte[] ct = ChaCha20Poly1305.encrypt(pt, null, key, nonce);
                ChaCha20Poly1305.decrypt(ct, null, key, nonce);
                long ns = System.nanoTime() - t0;
                mb[i] = (size * 2.0) / (ns / 1e9) / (1024*1024);
            }
            printStats("  " + fmtSize(size), mb, "MB/s");
        }
        System.out.println();
    }

    // ─── BLAKE3 ───────────────────────────────────────────────────────────────

    static void benchBLAKE3() {
        System.out.println("┌─────────────────────────────────────────────────────────────┐");
        System.out.println("│  BLAKE3                                                     │");
        System.out.println("└─────────────────────────────────────────────────────────────┘");
        int[] sizes = {1024, 16*1024, 64*1024, 1024*1024};
        for (int size : sizes) {
            byte[] data = RNG.randomBytes(size);
            gc();

            double[] mb = new double[RUNS];
            for (int i = 0; i < WARMUP; i++) BLAKE3.hash(data);
            for (int i = 0; i < RUNS; i++) {
                long t0 = System.nanoTime();
                BLAKE3.hash(data);
                long ns = System.nanoTime() - t0;
                mb[i] = (double)size / (ns / 1e9) / (1024*1024);
            }
            printStats("  " + fmtSize(size), mb, "MB/s");
        }
        System.out.println();
    }

    // ─── Kyber-1024 ───────────────────────────────────────────────────────────

    static void benchKyber() {
        System.out.println("┌─────────────────────────────────────────────────────────────┐");
        System.out.println("│  Kyber-1024                                                 │");
        System.out.println("└─────────────────────────────────────────────────────────────┘");
        gc();

        double[] kgMs = new double[RUNS];
        double[] enMs = new double[RUNS];
        double[] deMs = new double[RUNS];

        // Warmup
        for (int i = 0; i < WARMUP; i++) {
            byte[] seed = RNG.randomBytes(64);
            Kyber1024.KeyPair kp = Kyber1024.generateKeyPair(seed);
            Kyber1024.Encapsulation enc = Kyber1024.encapsulate(kp.publicKey, RNG.randomBytes(32));
            Kyber1024.decapsulate(enc.ciphertext, kp.secretKey);
        }

        // Measure each operation separately
        byte[] seed = RNG.randomBytes(64);
        Kyber1024.KeyPair kp = Kyber1024.generateKeyPair(seed);
        Kyber1024.Encapsulation enc = Kyber1024.encapsulate(kp.publicKey, RNG.randomBytes(32));

        for (int i = 0; i < RUNS; i++) {
            long t0 = System.nanoTime();
            kp = Kyber1024.generateKeyPair(RNG.randomBytes(64));
            kgMs[i] = (System.nanoTime() - t0) / 1e6;

            t0 = System.nanoTime();
            enc = Kyber1024.encapsulate(kp.publicKey, RNG.randomBytes(32));
            enMs[i] = (System.nanoTime() - t0) / 1e6;

            t0 = System.nanoTime();
            Kyber1024.decapsulate(enc.ciphertext, kp.secretKey);
            deMs[i] = (System.nanoTime() - t0) / 1e6;
        }

        printStats("  KeyGen  ", kgMs, "ms");
        printStats("  Encap   ", enMs, "ms");
        printStats("  Decap   ", deMs, "ms");
        System.out.println();
    }

    // ─── Statistics ───────────────────────────────────────────────────────────

    static void printStats(String label, double[] data, String unit) {
        double sum = 0, min = data[0], max = data[0];
        for (double v : data) { sum += v; min = Math.min(min, v); max = Math.max(max, v); }
        double mean = sum / data.length;
        double var = 0;
        for (double v : data) { double d = v - mean; var += d*d; }
        double stddev = Math.sqrt(var / data.length);
        double cv = stddev / mean * 100;

        System.out.printf("  %-12s │ mean: %8.1f %-5s │ min: %8.1f │ max: %8.1f │ σ: %5.1f%% %s%n",
            label, mean, unit, min, max, cv,
            cv > 15 ? "⚠ unstable" : cv < 5 ? "✓ stable" : "");
    }

    static String fmtSize(int bytes) {
        if (bytes < 1024) return bytes + "B";
        if (bytes < 1024*1024) return (bytes/1024) + "KB";
        return (bytes/1024/1024) + "MB";
    }

    static void gc() {
        System.gc(); System.gc();
        try { Thread.sleep(50); } catch (Exception e) {}
    }
}
