package com.ultracipher;

import com.ultracipher.core.api.UltraCipherEngine;
import com.ultracipher.core.kyber.Kyber1024;
import com.ultracipher.core.math.GaloisField;
import com.ultracipher.core.modes.AES256GCM;
import com.ultracipher.core.primitives.*;
import org.junit.jupiter.api.*;
import static org.junit.jupiter.api.Assertions.*;

import java.util.Arrays;

/**
 * Full test suite for UltraCipher.
 * Tests every algorithm against known test vectors and internal consistency.
 */
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
public class UltraCipherTest {

    private static final UltraSecureRandom RNG = new UltraSecureRandom();

    // ─── GF(2^8) Tests ────────────────────────────────────────────────────────

    @Test @Order(1)
    @DisplayName("GF(2^8): Multiplication identity")
    void testGFMultiplyIdentity() {
        for (int i = 1; i < 256; i++) {
            assertEquals(i, GaloisField.multiply(i, 1), "GF multiply by 1 should be identity");
        }
    }

    @Test @Order(2)
    @DisplayName("GF(2^8): Inverse correctness")
    void testGFInverse() {
        for (int i = 1; i < 256; i++) {
            int inv = GaloisField.inverse(i);
            assertEquals(1, GaloisField.multiply(i, inv), "a * a^-1 should be 1 in GF(2^8) for a=" + i);
        }
    }

    @Test @Order(3)
    @DisplayName("GF(2^8): Known multiplication values")
    void testGFKnownValues() {
        assertEquals(0x57, GaloisField.multiply(0x57, 0x01));
        assertEquals(0xAE, GaloisField.multiply(0x57, 0x02));
        // 0x57 * 4: xtime(0xAE) = 0x5C ^ 0x1B = 0x47 (0xAE has high bit set)
        assertEquals(0x47, GaloisField.multiply(0x57, 0x04));
        // From FIPS 197 test vectors: 0x57 * 0x13 = 0xFE
        assertEquals(0xFE, GaloisField.multiply(0x57, 0x13));
    }

    // ─── AES-256 Tests ────────────────────────────────────────────────────────

    @Test @Order(10)
    @DisplayName("AES-256: S-box self-consistency")
    void testAESSBox() {
        for (int i = 0; i < 256; i++) {
            int s = AES256.sbox(i);
            assertEquals(i, AES256.invSbox(s), "inv(sbox(x)) should be x");
        }
    }

    @Test @Order(11)
    @DisplayName("AES-256-GCM: Encrypt/Decrypt roundtrip")
    void testAESGCMRoundtrip() {
        byte[] key   = RNG.randomBytes(32);
        byte[] nonce = RNG.randomBytes(12);
        byte[] plaintext = "AES-256-GCM test message 12345!".getBytes();
        byte[] aad   = "additional authenticated data".getBytes();

        byte[] ct = AES256GCM.encrypt(plaintext, aad, key, nonce);
        byte[] pt = AES256GCM.decrypt(ct, aad, key, nonce);

        assertArrayEquals(plaintext, pt, "AES-256-GCM roundtrip failed");
    }

    @Test @Order(12)
    @DisplayName("AES-256-GCM: Tamper detection")
    void testAESGCMTamperDetection() {
        byte[] key   = RNG.randomBytes(32);
        byte[] nonce = RNG.randomBytes(12);
        byte[] pt    = "Secret data".getBytes();

        byte[] ct = AES256GCM.encrypt(pt, null, key, nonce);
        ct[0] ^= 0x01; // flip a bit

        assertThrows(SecurityException.class, () -> AES256GCM.decrypt(ct, null, key, nonce),
            "Should throw SecurityException on tampered ciphertext");
    }

    @Test @Order(13)
    @DisplayName("AES-256-GCM: Empty plaintext")
    void testAESGCMEmpty() {
        byte[] key   = RNG.randomBytes(32);
        byte[] nonce = RNG.randomBytes(12);
        byte[] ct = AES256GCM.encrypt(new byte[0], null, key, nonce);
        byte[] pt = AES256GCM.decrypt(ct, null, key, nonce);
        assertEquals(0, pt.length, "Decrypted empty should be empty");
    }

    // ─── ChaCha20-Poly1305 Tests ──────────────────────────────────────────────

    @Test @Order(20)
    @DisplayName("ChaCha20-Poly1305: Roundtrip")
    void testChaCha20Roundtrip() {
        byte[] key   = RNG.randomBytes(32);
        byte[] nonce = RNG.randomBytes(12);
        byte[] msg   = "ChaCha20-Poly1305 is blazing fast!".getBytes();
        byte[] aad   = "auth data".getBytes();

        byte[] ct = ChaCha20Poly1305.encrypt(msg, aad, key, nonce);
        byte[] pt = ChaCha20Poly1305.decrypt(ct, aad, key, nonce);

        assertArrayEquals(msg, pt, "ChaCha20-Poly1305 roundtrip failed");
    }

    @Test @Order(21)
    @DisplayName("ChaCha20-Poly1305: Tamper detection")
    void testChaCha20TamperDetection() {
        byte[] key   = RNG.randomBytes(32);
        byte[] nonce = RNG.randomBytes(12);
        byte[] ct    = ChaCha20Poly1305.encrypt("secret".getBytes(), null, key, nonce);
        ct[ct.length - 1] ^= 0xFF;

        assertThrows(SecurityException.class,
            () -> ChaCha20Poly1305.decrypt(ct, null, key, nonce));
    }

    @Test @Order(22)
    @DisplayName("ChaCha20-Poly1305: Large message (1MB)")
    void testChaCha20LargeMessage() {
        byte[] key   = RNG.randomBytes(32);
        byte[] nonce = RNG.randomBytes(12);
        byte[] big   = RNG.randomBytes(1024 * 1024);

        byte[] ct = ChaCha20Poly1305.encrypt(big, null, key, nonce);
        byte[] pt = ChaCha20Poly1305.decrypt(ct, null, key, nonce);

        assertArrayEquals(big, pt, "Large message roundtrip failed");
    }

    // ─── BLAKE3 Tests ─────────────────────────────────────────────────────────

    @Test @Order(30)
    @DisplayName("BLAKE3: Deterministic output")
    void testBLAKE3Deterministic() {
        byte[] data = "BLAKE3 test".getBytes();
        assertArrayEquals(BLAKE3.hash(data), BLAKE3.hash(data), "BLAKE3 must be deterministic");
    }

    @Test @Order(31)
    @DisplayName("BLAKE3: Different inputs produce different hashes")
    void testBLAKE3Collision() {
        byte[] h1 = BLAKE3.hash("input one".getBytes());
        byte[] h2 = BLAKE3.hash("input two".getBytes());
        assertFalse(Arrays.equals(h1, h2), "Different inputs should produce different hashes");
    }

    @Test @Order(32)
    @DisplayName("BLAKE3: Extended output (XOF)")
    void testBLAKE3XOF() {
        byte[] data  = "xof test".getBytes();
        byte[] out64 = BLAKE3.hash(data, 64);
        byte[] out32 = BLAKE3.hash(data, 32);
        assertEquals(64, out64.length);
        // First 32 bytes of 64-byte output should match 32-byte output (XOF property)
        // Note: BLAKE3 XOF first 32 bytes = 32-byte output
        assertArrayEquals(out32, Arrays.copyOf(out64, 32), "XOF first 32 bytes should match 32-byte hash");
    }

    @Test @Order(33)
    @DisplayName("BLAKE3: Keyed hash (MAC)")
    void testBLAKE3KeyedHash() {
        byte[] data = "message".getBytes();
        byte[] key1 = RNG.randomBytes(32);
        byte[] key2 = RNG.randomBytes(32);

        byte[] mac1a = BLAKE3.keyedHash(data, key1);
        byte[] mac1b = BLAKE3.keyedHash(data, key1);
        byte[] mac2  = BLAKE3.keyedHash(data, key2);

        assertArrayEquals(mac1a, mac1b, "Same key should produce same MAC");
        assertFalse(Arrays.equals(mac1a, mac2), "Different keys should produce different MACs");
    }

    // ─── Kyber-1024 Tests ─────────────────────────────────────────────────────

    @Test @Order(40)
    @DisplayName("Kyber-1024: Key generation")
    void testKyberKeyGen() {
        byte[] seed = RNG.randomBytes(64);
        Kyber1024.KeyPair kp = Kyber1024.generateKeyPair(seed);
        assertEquals(Kyber1024.PUBLIC_KEY_SIZE, kp.publicKey.length);
        assertEquals(Kyber1024.SECRET_KEY_SIZE, kp.secretKey.length);
    }

    @Test @Order(41)
    @DisplayName("Kyber-1024: Encapsulate/Decapsulate shared secret")
    void testKyberEncapDecap() {
        // Fixed seed for reproducibility
        byte[] seed = new byte[64];
        for (int i = 0; i < 64; i++) seed[i] = (byte)(i + 1);
        Kyber1024.KeyPair kp = Kyber1024.generateKeyPair(seed);

        byte[] randomSeed = new byte[32];
        for (int i = 0; i < 32; i++) randomSeed[i] = (byte)(0xAB);

        Kyber1024.Encapsulation enc = Kyber1024.encapsulate(kp.publicKey, randomSeed);
        byte[] sharedSecret = Kyber1024.decapsulate(enc.ciphertext, kp.secretKey);

        System.out.printf("encap SS: %02x %02x %02x %02x%n",
            enc.sharedSecret[0]&0xFF, enc.sharedSecret[1]&0xFF, enc.sharedSecret[2]&0xFF, enc.sharedSecret[3]&0xFF);
        System.out.printf("decap SS: %02x %02x %02x %02x%n",
            sharedSecret[0]&0xFF, sharedSecret[1]&0xFF, sharedSecret[2]&0xFF, sharedSecret[3]&0xFF);

        assertArrayEquals(enc.sharedSecret, sharedSecret,
            "Kyber shared secrets should match after encap/decap");
    }

    @Test @Order(42)
    @DisplayName("Kyber-1024: Wrong secret key produces different shared secret")
    void testKyberWrongKey() {
        Kyber1024.KeyPair kp1 = Kyber1024.generateKeyPair(RNG.randomBytes(64));
        Kyber1024.KeyPair kp2 = Kyber1024.generateKeyPair(RNG.randomBytes(64));

        Kyber1024.Encapsulation enc = Kyber1024.encapsulate(kp1.publicKey, RNG.randomBytes(32));
        byte[] wrongSecret = Kyber1024.decapsulate(enc.ciphertext, kp2.secretKey);

        assertFalse(Arrays.equals(enc.sharedSecret, wrongSecret),
            "Wrong secret key should produce different shared secret (implicit rejection)");
    }

    // ─── UltraCipherEngine Integration Tests ─────────────────────────────────

    @Test @Order(50)
    @DisplayName("Engine: Symmetric encryption roundtrip")
    void testEngineSymmetric() {
        UltraCipherEngine engine = new UltraCipherEngine();
        byte[] key = engine.generateKey();
        byte[] msg = "Ultra secure message!".getBytes();
        byte[] aad = "context".getBytes();

        UltraCipherEngine.EncryptedPacket packet = engine.encrypt(msg, key, aad);
        byte[] decrypted = engine.decrypt(packet, key, aad);

        assertArrayEquals(msg, decrypted, "Engine symmetric roundtrip failed");
    }

    @Test @Order(51)
    @DisplayName("Engine: Hybrid post-quantum roundtrip")
    void testEngineHybrid() {
        UltraCipherEngine engine = new UltraCipherEngine();
        Kyber1024.KeyPair kp = engine.generatePostQuantumKeyPair();
        byte[] msg = "Post-quantum secure message!".getBytes();

        UltraCipherEngine.HybridPacket packet = engine.hybridEncrypt(msg, kp.publicKey, null);
        byte[] decrypted = engine.hybridDecrypt(packet, kp.secretKey, null);

        assertArrayEquals(msg, decrypted, "Hybrid post-quantum roundtrip failed");
    }

    @Test @Order(52)
    @DisplayName("Engine: Packet serialization roundtrip")
    void testPacketSerialization() {
        UltraCipherEngine engine = new UltraCipherEngine();
        byte[] key = engine.generateKey();
        byte[] msg = "Serialization test".getBytes();

        UltraCipherEngine.EncryptedPacket packet = engine.encrypt(msg, key, null);
        byte[] bytes = packet.toBytes();
        UltraCipherEngine.EncryptedPacket restored = UltraCipherEngine.EncryptedPacket.fromBytes(bytes);
        byte[] decrypted = engine.decrypt(restored, key, null);

        assertArrayEquals(msg, decrypted, "Serialization roundtrip failed");
    }

    @Test @Order(53)
    @DisplayName("Engine: Password-derived key")
    void testPasswordDerivedKey() {
        UltraCipherEngine engine = new UltraCipherEngine();
        char[] password = "correct-horse-battery-staple".toCharArray();
        byte[] salt = engine.generateSalt();

        byte[] key1 = engine.deriveKeyFromPassword(password, salt, 32);
        byte[] key2 = engine.deriveKeyFromPassword(password, salt, 32);

        assertArrayEquals(key1, key2, "Same password+salt should produce same key");
        assertEquals(32, key1.length, "Key should be 32 bytes");
    }

    @Test @Order(60)
    @DisplayName("Security: Nonce uniqueness per encryption")
    void testNonceUniqueness() {
        UltraCipherEngine engine = new UltraCipherEngine();
        byte[] key = engine.generateKey();
        byte[] msg = "test".getBytes();

        UltraCipherEngine.EncryptedPacket p1 = engine.encrypt(msg, key, null);
        UltraCipherEngine.EncryptedPacket p2 = engine.encrypt(msg, key, null);

        assertFalse(Arrays.equals(p1.nonce, p2.nonce), "Each encryption should use a unique nonce!");
        assertFalse(Arrays.equals(p1.ciphertext, p2.ciphertext), "Same message, different nonces → different ciphertexts");
    }
}
