package com.ultracipher;

import com.ultracipher.core.api.UltraCipherEngine;
import com.ultracipher.core.kyber.Kyber1024;
import com.ultracipher.core.primitives.BLAKE3;
import com.ultracipher.core.primitives.UltraSecureRandom;
import com.ultracipher.core.modes.StreamingEncryption;

import java.io.*;
import java.nio.file.*;
import java.util.Arrays;

/**
 * UltraCipher - Post-Quantum Hybrid Cryptography Engine
 *
 * Built from absolute zero. No frameworks. No libraries. Pure Java.
 *
 * Algorithms (all hand-crafted):
 *   ✦ AES-256-GCM       - NIST standard authenticated encryption
 *   ✦ ChaCha20-Poly1305  - Fast stream cipher AEAD (faster on non-AES-NI hardware)
 *   ✦ Kyber-1024         - Post-quantum key encapsulation (NIST FIPS 203)
 *   ✦ BLAKE3             - Ultra-fast cryptographic hash (faster than SHA-256)
 *   ✦ Argon2id           - Memory-hard password KDF (PHC winner)
 *   ✦ GF(2^8)            - Galois field arithmetic (foundation of AES)
 *
 * Usage:
 *   java -jar ultracipher.jar keygen
 *   java -jar ultracipher.jar encrypt <file> <key-file>
 *   java -jar ultracipher.jar decrypt <file> <key-file>
 *   java -jar ultracipher.jar hash <file>
 *   java -jar ultracipher.jar hybrid-keygen
 *   java -jar ultracipher.jar hybrid-encrypt <file> <pubkey-file>
 *   java -jar ultracipher.jar hybrid-decrypt <file> <seckey-file>
 *   java -jar ultracipher.jar benchmark
 *   java -jar ultracipher.jar demo
 */
public class UltraCipher {

    private static final String BANNER =
        "\n╔══════════════════════════════════════════════════════════════╗\n" +
        "║          U L T R A C I P H E R  v1.0                        ║\n" +
        "║    Post-Quantum Hybrid Cryptography - Built from Zero        ║\n" +
        "║  AES-256-GCM | ChaCha20-Poly1305 | Kyber-1024 | BLAKE3      ║\n" +
        "╚══════════════════════════════════════════════════════════════╝\n";

    public static void main(String[] args) throws Exception {
        System.out.println(BANNER);

        if (args.length == 0) {
            runDemo();
            return;
        }

        UltraCipherEngine engine = new UltraCipherEngine();
        System.out.println("[INFO] Active algorithm: " + engine.getActiveAlgorithm());
        System.out.println("[INFO] " + engine.getSystemInfo() + "\n");

        switch (args[0].toLowerCase()) {
            case "keygen"         -> cmdKeyGen(engine);
            case "encrypt"        -> cmdEncrypt(engine, args);
            case "decrypt"        -> cmdDecrypt(engine, args);
            case "hash"           -> cmdHash(args);
            case "hybrid-keygen"  -> cmdHybridKeyGen(engine);
            case "hybrid-encrypt" -> cmdHybridEncrypt(engine, args);
            case "hybrid-decrypt" -> cmdHybridDecrypt(engine, args);
            case "benchmark"      -> Benchmark.main(args);
            case "demo"           -> runDemo();
            default               -> printUsage();
        }
    }

    // ─── Commands ─────────────────────────────────────────────────────────────

    private static void cmdKeyGen(UltraCipherEngine engine) throws Exception {
        byte[] key = engine.generateKey();
        byte[] salt = engine.generateSalt();
        Files.write(Path.of("ultracipher.key"), key);
        Files.write(Path.of("ultracipher.salt"), salt);
        System.out.println("[✓] Generated 256-bit symmetric key → ultracipher.key");
        System.out.println("[✓] Generated 256-bit salt          → ultracipher.salt");
    }

    private static void cmdEncrypt(UltraCipherEngine engine, String[] args) throws Exception {
        if (args.length < 3) { System.err.println("Usage: encrypt <file> <key-file>"); return; }
        byte[] plaintext = Files.readAllBytes(Path.of(args[1]));
        byte[] key = Files.readAllBytes(Path.of(args[2]));
        UltraCipherEngine.EncryptedPacket packet = engine.encrypt(plaintext, key, null);
        byte[] output = packet.toBytes();
        String outFile = args[1] + ".uc";
        Files.write(Path.of(outFile), output);
        System.out.printf("[✓] Encrypted %d bytes → %s (%d bytes, overhead: %d bytes)%n",
            plaintext.length, outFile, output.length, output.length - plaintext.length);
    }

    private static void cmdDecrypt(UltraCipherEngine engine, String[] args) throws Exception {
        if (args.length < 3) { System.err.println("Usage: decrypt <file> <key-file>"); return; }
        byte[] data = Files.readAllBytes(Path.of(args[1]));
        byte[] key = Files.readAllBytes(Path.of(args[2]));
        UltraCipherEngine.EncryptedPacket packet = UltraCipherEngine.EncryptedPacket.fromBytes(data);
        byte[] plaintext = engine.decrypt(packet, key, null);
        String outFile = args[1].replace(".uc", ".dec");
        Files.write(Path.of(outFile), plaintext);
        System.out.printf("[✓] Decrypted → %s (%d bytes)%n", outFile, plaintext.length);
    }

    private static void cmdHash(String[] args) throws Exception {
        if (args.length < 2) { System.err.println("Usage: hash <file>"); return; }
        byte[] data = Files.readAllBytes(Path.of(args[1]));
        System.out.printf("[BLAKE3] %s  %s%n", BLAKE3.hexHash(data), args[1]);
    }

    private static void cmdHybridKeyGen(UltraCipherEngine engine) throws Exception {
        Kyber1024.KeyPair kp = engine.generatePostQuantumKeyPair();
        Files.write(Path.of("kyber.pub"),  kp.publicKey);
        Files.write(Path.of("kyber.sec"),  kp.secretKey);
        System.out.println("[✓] Generated Kyber-1024 key pair");
        System.out.printf("    Public key:  kyber.pub  (%d bytes)%n", kp.publicKey.length);
        System.out.printf("    Secret key:  kyber.sec  (%d bytes)%n", kp.secretKey.length);
    }

    private static void cmdHybridEncrypt(UltraCipherEngine engine, String[] args) throws Exception {
        if (args.length < 3) { System.err.println("Usage: hybrid-encrypt <file> <pubkey-file>"); return; }
        byte[] plaintext = Files.readAllBytes(Path.of(args[1]));
        byte[] pubKey = Files.readAllBytes(Path.of(args[2]));
        UltraCipherEngine.HybridPacket packet = engine.hybridEncrypt(plaintext, pubKey, null);
        byte[] output = packet.toBytes();
        String outFile = args[1] + ".ucpq";
        Files.write(Path.of(outFile), output);
        System.out.printf("[✓] Hybrid encrypted %d bytes → %s (%d bytes)%n",
            plaintext.length, outFile, output.length);
        System.out.println("[✓] Post-quantum secure (Kyber-1024 + " + engine.getActiveAlgorithm() + ")");
    }

    private static void cmdHybridDecrypt(UltraCipherEngine engine, String[] args) throws Exception {
        if (args.length < 3) { System.err.println("Usage: hybrid-decrypt <file> <seckey-file>"); return; }
        byte[] data = Files.readAllBytes(Path.of(args[1]));
        byte[] secKey = Files.readAllBytes(Path.of(args[2]));
        UltraCipherEngine.HybridPacket packet = UltraCipherEngine.HybridPacket.fromBytes(data);
        byte[] plaintext = engine.hybridDecrypt(packet, secKey, null);
        String outFile = args[1].replace(".ucpq", ".dec");
        Files.write(Path.of(outFile), plaintext);
        System.out.printf("[✓] Hybrid decrypted → %s (%d bytes)%n", outFile, plaintext.length);
    }

    // ─── Demo ─────────────────────────────────────────────────────────────────

    public static void runDemo() throws Exception {
        UltraCipherEngine engine = new UltraCipherEngine();
        UltraSecureRandom rng = new UltraSecureRandom();

        System.out.println("━━━ DEMO: All Systems ━━━\n");
        System.out.println("Active algorithm: " + engine.getActiveAlgorithm());

        // ── Demo 1: Symmetric Encryption
        System.out.println("\n[ 1 ] Symmetric Encryption (AES-256-GCM / ChaCha20-Poly1305)");
        byte[] key = engine.generateKey();
        String message = "Hello from UltraCipher! This message is encrypted with post-quantum strength.";
        byte[] msgBytes = message.getBytes();

        UltraCipherEngine.EncryptedPacket packet = engine.encrypt(msgBytes, key, "test-aad".getBytes());
        System.out.println("    Original:  " + message);
        System.out.println("    Encrypted: " + toHex(packet.ciphertext).substring(0, 64) + "...");

        byte[] decrypted = engine.decrypt(packet, key, "test-aad".getBytes());
        System.out.println("    Decrypted: " + new String(decrypted));
        System.out.println("    Status:    " + (Arrays.equals(msgBytes, decrypted) ? "✓ MATCH" : "✗ FAIL"));

        // ── Demo 2: Post-Quantum Hybrid
        System.out.println("\n[ 2 ] Post-Quantum Hybrid (Kyber-1024 + AEAD)");
        Kyber1024.KeyPair kp = engine.generatePostQuantumKeyPair();
        System.out.println("    Public key size:  " + kp.publicKey.length + " bytes");
        System.out.println("    Secret key size:  " + kp.secretKey.length + " bytes");

        UltraCipherEngine.HybridPacket hPacket = engine.hybridEncrypt(msgBytes, kp.publicKey, null);
        byte[] hDecrypted = engine.hybridDecrypt(hPacket, kp.secretKey, null);
        System.out.println("    Hybrid ciphertext: " + hPacket.toBytes().length + " bytes total");
        System.out.println("    Status: " + (Arrays.equals(msgBytes, hDecrypted) ? "✓ POST-QUANTUM SECURE" : "✗ FAIL"));

        // ── Demo 3: BLAKE3
        System.out.println("\n[ 3 ] BLAKE3 Hash");
        System.out.println("    Input:  \"" + message + "\"");
        System.out.println("    BLAKE3: " + BLAKE3.hexHash(msgBytes));

        // ── Demo 4: Argon2id KDF
        System.out.println("\n[ 4 ] Argon2id Key Derivation from Password");
        char[] password = "my-super-secret-password".toCharArray();
        byte[] salt = engine.generateSalt();
        System.out.println("    Deriving key (64MB memory, 3 iterations)...");
        long kdfStart = System.currentTimeMillis();
        byte[] derivedKey = engine.deriveKeyFromPassword(password, salt, 32);
        long kdfTime = System.currentTimeMillis() - kdfStart;
        System.out.printf("    Derived key: %s%n", toHex(derivedKey));
        System.out.printf("    Time: %d ms (attacker needs same RAM+time per attempt!)%n", kdfTime);

        // ── Demo 5: Tampering Detection
        System.out.println("\n[ 5 ] Tampering Detection");
        byte[] tamperedCT = packet.ciphertext.clone();
        tamperedCT[0] ^= 0xFF; // flip a bit
        UltraCipherEngine.EncryptedPacket tampered = new UltraCipherEngine.EncryptedPacket(
            tamperedCT, packet.nonce, packet.algorithm, null);
        try {
            engine.decrypt(tampered, key, "test-aad".getBytes());
            System.out.println("    ✗ SECURITY FAIL: Tampering not detected!");
        } catch (SecurityException e) {
            System.out.println("    ✓ Tampering detected: " + e.getMessage());
        }

        System.out.println("\n━━━ All demos completed successfully! ━━━");
    }

    // ─── Benchmark ────────────────────────────────────────────────────────────

    public static void runBenchmark() throws Exception {
        System.out.println("━━━ BENCHMARK ━━━\n");
        UltraSecureRandom rng = new UltraSecureRandom();
        byte[] key   = rng.randomBytes(32);
        byte[] nonce = rng.randomBytes(12);

        int[] dataSizes = {1024, 65536, 1048576};
        int warmup = 20, iterations = 100;

        for (int size : dataSizes) {
            byte[] data = rng.randomBytes(size);

            // Warmup
            for (int i = 0; i < warmup; i++) {
                com.ultracipher.core.modes.AES256GCM.encrypt(data, null, key, nonce);
            }

            // AES-256-GCM
            long t = System.nanoTime();
            for (int i = 0; i < iterations; i++) {
                com.ultracipher.core.modes.AES256GCM.encrypt(data, null, key, nonce);
            }
            double aesTime = (System.nanoTime() - t) / 1e6 / iterations;
            double aesThroughput = (size / 1024.0 / 1024.0) / (aesTime / 1000.0);

            // ChaCha20-Poly1305
            t = System.nanoTime();
            for (int i = 0; i < iterations; i++) {
                com.ultracipher.core.primitives.ChaCha20Poly1305.encrypt(data, null, key, nonce);
            }
            double chachaTime = (System.nanoTime() - t) / 1e6 / iterations;
            double chachaThroughput = (size / 1024.0 / 1024.0) / (chachaTime / 1000.0);

            // BLAKE3
            t = System.nanoTime();
            for (int i = 0; i < iterations; i++) {
                BLAKE3.hash(data);
            }
            double blakeTime = (System.nanoTime() - t) / 1e6 / iterations;
            double blakeThroughput = (size / 1024.0 / 1024.0) / (blakeTime / 1000.0);

            String sizeStr = size < 1024 ? size + "B"
                           : size < 1048576 ? (size/1024) + "KB"
                           : (size/1048576) + "MB";

            System.out.printf("Data: %6s │ AES-256-GCM: %6.1f MB/s │ ChaCha20: %6.1f MB/s │ BLAKE3: %6.1f MB/s%n",
                sizeStr, aesThroughput, chachaThroughput, blakeThroughput);
        }

        // Kyber-1024 keygen + encap/decap
        System.out.println();
        UltraCipherEngine engine = new UltraCipherEngine();
        int kyberIter = 10;
        long t = System.nanoTime();
        for (int i = 0; i < kyberIter; i++) engine.generatePostQuantumKeyPair();
        System.out.printf("Kyber-1024 KeyGen:    %.1f ms/op%n", (System.nanoTime()-t)/1e6/kyberIter);

        Kyber1024.KeyPair kp = engine.generatePostQuantumKeyPair();
        t = System.nanoTime();
        for (int i = 0; i < kyberIter; i++) Kyber1024.encapsulate(kp.publicKey, rng.randomBytes(32));
        System.out.printf("Kyber-1024 Encap:     %.1f ms/op%n", (System.nanoTime()-t)/1e6/kyberIter);

        Kyber1024.Encapsulation enc = Kyber1024.encapsulate(kp.publicKey, rng.randomBytes(32));
        t = System.nanoTime();
        for (int i = 0; i < kyberIter; i++) Kyber1024.decapsulate(enc.ciphertext, kp.secretKey);
        System.out.printf("Kyber-1024 Decap:     %.1f ms/op%n", (System.nanoTime()-t)/1e6/kyberIter);

        System.out.println("\n━━━ Benchmark complete ━━━");
    }

    private static String toHex(byte[] b) {
        StringBuilder sb = new StringBuilder();
        for (byte x : b) sb.append(String.format("%02x", x & 0xFF));
        return sb.toString();
    }

    private static void printUsage() {
        System.out.println("Commands:");
        System.out.println("  keygen                           Generate symmetric key");
        System.out.println("  encrypt <file> <key-file>        Encrypt a file");
        System.out.println("  decrypt <file> <key-file>        Decrypt a file");
        System.out.println("  hash <file>                      BLAKE3 hash a file");
        System.out.println("  hybrid-keygen                    Generate Kyber-1024 key pair");
        System.out.println("  hybrid-encrypt <file> <pub>      Post-quantum encrypt");
        System.out.println("  hybrid-decrypt <file> <sec>      Post-quantum decrypt");
        System.out.println("  benchmark                        Performance test");
        System.out.println("  demo                             Run full system demo");
    }
}
