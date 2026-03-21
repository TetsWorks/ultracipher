package com.ultracipher.core.api;

import com.ultracipher.core.kyber.Kyber1024;
import com.ultracipher.core.modes.AES256GCM;
import com.ultracipher.core.primitives.*;

/**
 * UltraCipherEngine - the unified API for the entire cryptography system.
 *
 * Provides:
 * 1. SYMMETRIC encryption (AES-256-GCM or ChaCha20-Poly1305, auto-selected)
 * 2. HYBRID encryption (Kyber-1024 + symmetric AEAD - post-quantum secure)
 * 3. KEY DERIVATION (Argon2id for passwords, BLAKE3 for key material)
 * 4. HASHING (BLAKE3)
 * 5. Automatic algorithm selection based on hardware detection
 *
 * Every operation is from absolute zero. Zero external dependencies.
 */
public final class UltraCipherEngine {

    /**
     * Algorithm preference.
     */
    public enum Algorithm {
        AES_256_GCM,
        CHACHA20_POLY1305,
        AUTO  // Engine picks fastest for this hardware
    }

    /**
     * Encryption mode.
     */
    public enum Mode {
        SYMMETRIC,    // Shared-key encryption
        HYBRID        // Kyber KEM + symmetric (post-quantum)
    }

    private final Algorithm algorithm;
    private final UltraSecureRandom rng;

    // ─── Constructor ──────────────────────────────────────────────────────────

    public UltraCipherEngine() {
        this(Algorithm.AUTO);
    }

    public UltraCipherEngine(Algorithm algorithm) {
        this.rng = new UltraSecureRandom();
        this.algorithm = (algorithm == Algorithm.AUTO) ? detectFastestAlgorithm() : algorithm;
    }

    /**
     * Detect whether AES-NI hardware acceleration is available.
     * On hardware without AES-NI, ChaCha20 is significantly faster.
     */
    private Algorithm detectFastestAlgorithm() {
        // Benchmark both algorithms on a small input
        byte[] testKey = new byte[32];
        byte[] testNonce = new byte[12];
        byte[] testData = new byte[1024];
        rng.nextBytes(testKey);
        rng.nextBytes(testNonce);
        rng.nextBytes(testData);

        int[] aesKeys = com.ultracipher.core.primitives.AES256.expandKey(testKey);

        long start = System.nanoTime();
        for (int i = 0; i < 100; i++) {
            AES256GCM.encrypt(testData, null, testKey, testNonce);
        }
        long aesTime = System.nanoTime() - start;

        start = System.nanoTime();
        for (int i = 0; i < 100; i++) {
            ChaCha20Poly1305.encrypt(testData, null, testKey, testNonce);
        }
        long chachaTime = System.nanoTime() - start;

        return (chachaTime < aesTime) ? Algorithm.CHACHA20_POLY1305 : Algorithm.AES_256_GCM;
    }

    // ─── Symmetric Encryption ─────────────────────────────────────────────────

    /**
     * Encrypt data with a symmetric key.
     * Algorithm is auto-selected based on hardware performance.
     *
     * @param plaintext  data to encrypt
     * @param key        32-byte key
     * @param aad        additional authenticated data (optional, can be null)
     * @return EncryptedPacket containing ciphertext, nonce, and algorithm ID
     */
    public EncryptedPacket encrypt(byte[] plaintext, byte[] key, byte[] aad) {
        validateKey(key);
        byte[] nonce = rng.randomBytes(12);
        byte[] ciphertext;

        if (algorithm == Algorithm.AES_256_GCM) {
            ciphertext = AES256GCM.encrypt(plaintext, aad, key, nonce);
        } else {
            ciphertext = ChaCha20Poly1305.encrypt(plaintext, aad, key, nonce);
        }

        return new EncryptedPacket(ciphertext, nonce, algorithm, null);
    }

    /**
     * Decrypt a symmetric packet.
     */
    public byte[] decrypt(EncryptedPacket packet, byte[] key, byte[] aad) {
        validateKey(key);
        if (packet.algorithm == Algorithm.AES_256_GCM) {
            return AES256GCM.decrypt(packet.ciphertext, aad, key, packet.nonce);
        } else {
            return ChaCha20Poly1305.decrypt(packet.ciphertext, aad, key, packet.nonce);
        }
    }

    // ─── Hybrid Post-Quantum Encryption ───────────────────────────────────────

    /**
     * Generate a Kyber-1024 post-quantum key pair.
     * The public key can be shared openly.
     * The secret key must be kept private.
     *
     * @return Kyber1024.KeyPair with publicKey (1568 bytes) and secretKey (3168 bytes)
     */
    public Kyber1024.KeyPair generatePostQuantumKeyPair() {
        byte[] seed = rng.randomBytes(64);
        return Kyber1024.generateKeyPair(seed);
    }

    /**
     * Encrypt using hybrid post-quantum encryption.
     * Uses Kyber-1024 for key encapsulation + AES-256-GCM or ChaCha20 for data.
     *
     * This is secure against both classical and quantum computers.
     *
     * @param plaintext   data to encrypt
     * @param recipientPK recipient's Kyber public key
     * @param aad         additional data to authenticate
     * @return HybridPacket containing KEM ciphertext + encrypted data
     */
    public HybridPacket hybridEncrypt(byte[] plaintext, byte[] recipientPK, byte[] aad) {
        // 1. Kyber KEM: encapsulate shared secret
        byte[] seed = rng.randomBytes(32);
        Kyber1024.Encapsulation enc = Kyber1024.encapsulate(recipientPK, seed);

        // 2. Derive symmetric key from shared secret via BLAKE3 KDF
        byte[] symmetricKey = BLAKE3.deriveKey(
            "UltraCipher.hybridEncrypt.symmetricKey v1",
            enc.sharedSecret, 32
        );

        // 3. Encrypt data with symmetric key
        byte[] nonce = rng.randomBytes(12);
        byte[] ciphertext;
        if (algorithm == Algorithm.AES_256_GCM) {
            ciphertext = AES256GCM.encrypt(plaintext, aad, symmetricKey, nonce);
        } else {
            ciphertext = ChaCha20Poly1305.encrypt(plaintext, aad, symmetricKey, nonce);
        }

        return new HybridPacket(enc.ciphertext, ciphertext, nonce, algorithm);
    }

    /**
     * Decrypt a hybrid post-quantum packet.
     *
     * @param packet    received HybridPacket
     * @param secretKey recipient's Kyber secret key
     * @param aad       additional authenticated data
     * @return decrypted plaintext
     */
    public byte[] hybridDecrypt(HybridPacket packet, byte[] secretKey, byte[] aad) {
        // 1. Kyber KEM: decapsulate shared secret
        byte[] sharedSecret = Kyber1024.decapsulate(packet.kemCiphertext, secretKey);

        // 2. Derive symmetric key
        byte[] symmetricKey = BLAKE3.deriveKey(
            "UltraCipher.hybridEncrypt.symmetricKey v1",
            sharedSecret, 32
        );

        // 3. Decrypt data
        if (packet.algorithm == Algorithm.AES_256_GCM) {
            return AES256GCM.decrypt(packet.dataCiphertext, aad, symmetricKey, packet.nonce);
        } else {
            return ChaCha20Poly1305.decrypt(packet.dataCiphertext, aad, symmetricKey, packet.nonce);
        }
    }

    // ─── Key Derivation ───────────────────────────────────────────────────────

    /**
     * Derive cryptographic key from password using Argon2id.
     * Memory-hard, GPU-resistant, quantum-resistant output.
     *
     * @param password   user password
     * @param salt       random salt (use generateSalt())
     * @param outputLen  desired key length in bytes
     */
    public byte[] deriveKeyFromPassword(char[] password, byte[] salt, int outputLen) {
        byte[] passBytes = charsToBytes(password);
        try {
            return Argon2id.hashPassword(passBytes, salt, outputLen);
        } finally {
            // Wipe password bytes from memory
            java.util.Arrays.fill(passBytes, (byte) 0);
        }
    }

    /**
     * Derive key from existing key material (not a password).
     * Uses BLAKE3 KDF - extremely fast.
     */
    public byte[] deriveKey(String context, byte[] keyMaterial, int outputLen) {
        return BLAKE3.deriveKey(context, keyMaterial, outputLen);
    }

    /**
     * Generate a cryptographically random salt.
     */
    public byte[] generateSalt() {
        return rng.randomBytes(32);
    }

    /**
     * Generate a random symmetric key.
     */
    public byte[] generateKey() {
        return rng.randomBytes(32);
    }

    // ─── Hashing ──────────────────────────────────────────────────────────────

    /**
     * Hash data with BLAKE3. Output is 32 bytes by default.
     */
    public byte[] hash(byte[] data) {
        return BLAKE3.hash(data);
    }

    /**
     * Hash data with BLAKE3, variable output length.
     */
    public byte[] hash(byte[] data, int outputLen) {
        return BLAKE3.hash(data, outputLen);
    }

    /**
     * BLAKE3-MAC: keyed hash for message authentication.
     */
    public byte[] mac(byte[] data, byte[] key) {
        return BLAKE3.keyedHash(data, key);
    }

    // ─── Info ─────────────────────────────────────────────────────────────────

    public Algorithm getActiveAlgorithm() { return algorithm; }

    public String getSystemInfo() {
        return "UltraCipher v1.0 | Active: " + algorithm
             + " | Kyber-1024 (post-quantum) | BLAKE3 | Argon2id | Built from zero";
    }

    // ─── Utility ──────────────────────────────────────────────────────────────

    private void validateKey(byte[] key) {
        if (key == null || key.length != 32) {
            throw new IllegalArgumentException("UltraCipher requires a 32-byte (256-bit) key");
        }
    }

    private byte[] charsToBytes(char[] chars) {
        byte[] bytes = new byte[chars.length * 2];
        for (int i = 0; i < chars.length; i++) {
            bytes[i * 2]     = (byte)(chars[i] >> 8);
            bytes[i * 2 + 1] = (byte)(chars[i]);
        }
        return bytes;
    }

    // ─── Data Classes ─────────────────────────────────────────────────────────

    /**
     * Result of symmetric encryption. Contains everything needed to decrypt.
     */
    public static final class EncryptedPacket {
        public final byte[] ciphertext;
        public final byte[] nonce;
        public final Algorithm algorithm;
        public final byte[] aad; // may be null

        public EncryptedPacket(byte[] ciphertext, byte[] nonce, Algorithm algorithm, byte[] aad) {
            this.ciphertext = ciphertext;
            this.nonce = nonce;
            this.algorithm = algorithm;
            this.aad = aad;
        }

        /** Serialize to bytes: [1 byte alg][12 byte nonce][ciphertext] */
        public byte[] toBytes() {
            byte[] out = new byte[1 + 12 + ciphertext.length];
            out[0] = (byte)(algorithm == Algorithm.AES_256_GCM ? 1 : 2);
            System.arraycopy(nonce, 0, out, 1, 12);
            System.arraycopy(ciphertext, 0, out, 13, ciphertext.length);
            return out;
        }

        public static EncryptedPacket fromBytes(byte[] data) {
            Algorithm alg = (data[0] == 1) ? Algorithm.AES_256_GCM : Algorithm.CHACHA20_POLY1305;
            byte[] nonce = new byte[12];
            System.arraycopy(data, 1, nonce, 0, 12);
            byte[] ct = new byte[data.length - 13];
            System.arraycopy(data, 13, ct, 0, ct.length);
            return new EncryptedPacket(ct, nonce, alg, null);
        }
    }

    /**
     * Result of hybrid post-quantum encryption.
     */
    public static final class HybridPacket {
        public final byte[] kemCiphertext;    // Kyber-1024 KEM output
        public final byte[] dataCiphertext;   // Symmetric AEAD output
        public final byte[] nonce;
        public final Algorithm algorithm;

        public HybridPacket(byte[] kemCT, byte[] dataCT, byte[] nonce, Algorithm alg) {
            this.kemCiphertext  = kemCT;
            this.dataCiphertext = dataCT;
            this.nonce = nonce;
            this.algorithm = alg;
        }

        public byte[] toBytes() {
            int kemLen  = kemCiphertext.length;
            int dataLen = dataCiphertext.length;
            byte[] out  = new byte[1 + 4 + 4 + 12 + kemLen + dataLen];
            int pos = 0;
            out[pos++] = (byte)(algorithm == Algorithm.AES_256_GCM ? 1 : 2);
            writeInt(out, pos, kemLen);  pos += 4;
            writeInt(out, pos, dataLen); pos += 4;
            System.arraycopy(nonce, 0, out, pos, 12); pos += 12;
            System.arraycopy(kemCiphertext,  0, out, pos, kemLen);  pos += kemLen;
            System.arraycopy(dataCiphertext, 0, out, pos, dataLen);
            return out;
        }

        public static HybridPacket fromBytes(byte[] data) {
            int pos = 0;
            Algorithm alg = (data[pos++] == 1) ? Algorithm.AES_256_GCM : Algorithm.CHACHA20_POLY1305;
            int kemLen  = readInt(data, pos); pos += 4;
            int dataLen = readInt(data, pos); pos += 4;
            byte[] nonce = new byte[12];
            System.arraycopy(data, pos, nonce, 0, 12); pos += 12;
            byte[] kemCT = new byte[kemLen];
            System.arraycopy(data, pos, kemCT, 0, kemLen); pos += kemLen;
            byte[] dataCT = new byte[dataLen];
            System.arraycopy(data, pos, dataCT, 0, dataLen);
            return new HybridPacket(kemCT, dataCT, nonce, alg);
        }

        private static void writeInt(byte[] b, int off, int v) {
            b[off]=(byte)(v>>24); b[off+1]=(byte)(v>>16); b[off+2]=(byte)(v>>8); b[off+3]=(byte)v;
        }
        private static int readInt(byte[] b, int off) {
            return ((b[off]&0xFF)<<24)|((b[off+1]&0xFF)<<16)|((b[off+2]&0xFF)<<8)|(b[off+3]&0xFF);
        }
    }
}
