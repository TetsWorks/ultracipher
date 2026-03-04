# UltraCipher v1.0
### Motor de Criptografia Híbrida Pós-Quântica — Construído do Zero Absoluto

Zero dependências externas. Zero frameworks. Java puro.
Cada bit da matemática criptográfica implementado manualmente.

---

## Algoritmos (Todos Implementados à Mão)

| Algoritmo | Finalidade | Nível de Segurança |
|-----------|------------|-------------------|
| AES-256-GCM | Criptografia autenticada | 256 bits clássico |
| ChaCha20-Poly1305 | Cifra de fluxo rápida com AEAD | 256 bits clássico |
| Kyber-1024 | Encapsulamento de chave pós-quântico (NIST FIPS 203) | ~256 bits pós-quântico |
| BLAKE3 | Hash criptográfico + KDF + MAC | 256 bits |
| Argon2id | KDF de senha resistente a memória (vencedor do PHC) | Configurável |
| GF(2⁸) | Aritmética de campo de Galois | Base do AES |

---

## Arquitetura

```
ultracipher/
├── core/
│   ├── math/
│   │   └── GaloisField.java       ← Aritmética GF(2^8): inverso, multiplicação, xtime
│   ├── primitives/
│   │   ├── AES256.java            ← AES-256 completo (S-box, KeyExpansion, todas as rodadas)
│   │   ├── ChaCha20Poly1305.java  ← Cifra ChaCha20 + MAC Poly1305
│   │   ├── BLAKE3.java            ← Hash BLAKE3 (árvore de Merkle, modo XOF)
│   │   ├── Argon2id.java          ← KDF Argon2id (resistente a memória)
│   │   └── UltraSecureRandom.java ← CSPRNG baseado em ChaCha20
│   ├── modes/
│   │   ├── AES256GCM.java         ← Modo GCM (GHASH + CTR)
│   │   └── StreamingEncryption.java ← AEAD com criptografia em blocos (streaming)
│   ├── kyber/
│   │   └── Kyber1024.java         ← KEM Kyber-1024 (NTT, aritmética em reticulados)
│   └── api/
│       └── UltraCipherEngine.java ← API unificada + seleção automática de algoritmo
└── UltraCipher.java               ← Ponto de entrada CLI
```

---

## Build & Execução

# Compilar
mvn package

# Demo (executa todos os sistemas)
java -jar target/ultracipher-1.0.0.jar demo

# Benchmark
java -jar target/ultracipher-1.0.0.jar benchmark

# Gerar chave
java -jar target/ultracipher-1.0.0.jar keygen

# Criptografar arquivo (simétrico)
java -jar target/ultracipher-1.0.0.jar encrypt secret.txt ultracipher.key

# Descriptografar
java -jar target/ultracipher-1.0.0.jar decrypt secret.txt.uc ultracipher.key

# Gerar par de chaves pós-quântico
java -jar target/ultracipher-1.0.0.jar hybrid-keygen

# Criptografia pós-quântica
java -jar target/ultracipher-1.0.0.jar hybrid-encrypt secret.txt kyber.pub

# Descriptografia pós-quântica
java -jar target/ultracipher-1.0.0.jar hybrid-decrypt secret.txt.ucpq kyber.sec

# Rodar testes
mvn test

---

## API Java

// Criptografia simétrica
UltraCipherEngine engine = new UltraCipherEngine();
byte[] key = engine.generateKey();
EncryptedPacket packet = engine.encrypt(plaintext, key, aad);
byte[] recovered = engine.decrypt(packet, key, aad);

// Criptografia híbrida pós-quântica
KeyPair kp = engine.generatePostQuantumKeyPair();
HybridPacket hybrid = engine.hybridEncrypt(plaintext, kp.publicKey, aad);
byte[] recovered = engine.hybridDecrypt(hybrid, kp.secretKey, aad);

// Derivação de chave a partir de senha
byte[] salt = engine.generateSalt();
byte[] key = engine.deriveKeyFromPassword(password, salt, 32);

// Hash
byte[] hash = engine.hash(data);
byte[] mac  = engine.mac(data, key);

---

## Notas de Segurança

- Reutilizar nonce é catastrófico no GCM. UltraCipher gera automaticamente um nonce aleatório novo a cada criptografia.
- Argon2id usa 64MB de RAM e 3 iterações por padrão. Aumente para maior segurança.
- Kyber-1024 oferece segurança contra adversários clássicos e quânticos (Algoritmo de Shor).
- Todas as comparações de tag usam comparação em tempo constante para evitar ataques de timing.
- Material de chave secreta é apagado da memória após o uso sempre que possível.

---

## Matemática

Todas as operações são derivadas dos primeiros princípios:

- GF(2⁸): Polinômio irredutível x⁸ + x⁴ + x³ + x + 1 (FIPS 197)
- S-box do AES: calculada como affine_transform(GF_inverse(x))
- NTT: Borboleta Cooley-Tukey sobre Z_3329[x]/(x²⁵⁶+1)
- Poly1305: Avaliação polinomial sobre GF(2¹³⁰ - 5)
- ChaCha20: Estrutura ARX (Add-Rotate-XOR), 20 rodadas.
