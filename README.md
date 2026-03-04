# UltraCipher v1.0
### Post-Quantum Hybrid Cryptography Engine — Built from Absolute Zero

**Zero external dependencies. Zero frameworks. Pure Java.**  
Every bit of cryptographic mathematics implemented by hand.

---

## Algorithms (All Hand-Crafted)

| Algorithm | Purpose | Security Level |
|-----------|---------|---------------|
| **AES-256-GCM** | Authenticated encryption | 256-bit classical |
| **ChaCha20-Poly1305** | Fast stream cipher AEAD | 256-bit classical |
| **Kyber-1024** | Post-quantum key encapsulation (NIST FIPS 203) | ~256-bit post-quantum |
| **BLAKE3** | Cryptographic hash + KDF + MAC | 256-bit |
| **Argon2id** | Memory-hard password KDF (PHC winner) | Configurable |
| **GF(2⁸)** | Galois field arithmetic | Foundation of AES |

---

## Architecture

```
ultracipher/
├── core/
│   ├── math/
│   │   └── GaloisField.java       ← GF(2^8) arithmetic: inverse, multiply, xtime
│   ├── primitives/
│   │   ├── AES256.java            ← Full AES-256 (S-box, KeyExpansion, all rounds)
│   │   ├── ChaCha20Poly1305.java  ← ChaCha20 stream cipher + Poly1305 MAC
│   │   ├── BLAKE3.java            ← BLAKE3 hash (Merkle tree, XOF mode)
│   │   ├── Argon2id.java          ← Argon2id KDF (memory-hard)
│   │   └── UltraSecureRandom.java ← ChaCha20-based CSPRNG
│   ├── modes/
│   │   ├── AES256GCM.java         ← GCM mode (GHASH + CTR)
│   │   └── StreamingEncryption.java ← Chunked streaming AEAD
│   ├── kyber/
│   │   └── Kyber1024.java         ← Kyber-1024 KEM (NTT, lattice arithmetic)
│   └── api/
│       └── UltraCipherEngine.java ← Unified API + auto algorithm selection
└── UltraCipher.java               ← CLI entry point
```

---

## Build & Run

```bash
# Build
mvn package

# Demo (runs all systems)
java -jar target/ultracipher-1.0.0.jar demo

# Benchmark
java -jar target/ultracipher-1.0.0.jar benchmark

# Generate key
java -jar target/ultracipher-1.0.0.jar keygen

# Encrypt a file (symmetric)
java -jar target/ultracipher-1.0.0.jar encrypt secret.txt ultracipher.key

# Decrypt
java -jar target/ultracipher-1.0.0.jar decrypt secret.txt.uc ultracipher.key

# Generate post-quantum key pair
java -jar target/ultracipher-1.0.0.jar hybrid-keygen

# Post-quantum encrypt
java -jar target/ultracipher-1.0.0.jar hybrid-encrypt secret.txt kyber.pub

# Post-quantum decrypt
java -jar target/ultracipher-1.0.0.jar hybrid-decrypt secret.txt.ucpq kyber.sec

# Run tests
mvn test
```

---

## Java API

```java
// Symmetric encryption
UltraCipherEngine engine = new UltraCipherEngine();
byte[] key = engine.generateKey();
EncryptedPacket packet = engine.encrypt(plaintext, key, aad);
byte[] recovered = engine.decrypt(packet, key, aad);

// Post-quantum hybrid encryption
KeyPair kp = engine.generatePostQuantumKeyPair();
HybridPacket hybrid = engine.hybridEncrypt(plaintext, kp.publicKey, aad);
byte[] recovered = engine.hybridDecrypt(hybrid, kp.secretKey, aad);

// Key derivation from password
byte[] salt = engine.generateSalt();
byte[] key = engine.deriveKeyFromPassword(password, salt, 32);

// Hashing
byte[] hash = engine.hash(data);
byte[] mac  = engine.mac(data, key);
```

---

## Security Notes

- **Nonce reuse is catastrophic** for GCM. UltraCipher generates a fresh random nonce per encryption automatically.
- **Argon2id** uses 64MB RAM and 3 iterations by default. Increase for higher security.
- **Kyber-1024** provides security against both classical and quantum adversaries (Shor's algorithm).
- All tag comparisons use **constant-time** comparison to prevent timing attacks.
- Secret key material is wiped from memory after use where possible.

---

## Mathematics

Every operation is derived from first principles:

- **GF(2⁸)**: Irreducible polynomial `x⁸ + x⁴ + x³ + x + 1` (FIPS 197)
- **AES S-box**: Computed as `affine_transform(GF_inverse(x))`
- **NTT**: Cooley-Tukey butterfly over `Z_3329[x]/(x²⁵⁶+1)`
- **Poly1305**: Polynomial evaluation over `GF(2¹³⁰ - 5)`
- **ChaCha20**: ARX (Add-Rotate-XOR) design, 20 rounds

Built with 🔥 from absolute zero.
