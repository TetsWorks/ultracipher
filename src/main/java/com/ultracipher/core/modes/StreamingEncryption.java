package com.ultracipher.core.modes;

import com.ultracipher.core.primitives.BLAKE3;
import com.ultracipher.core.primitives.ChaCha20Poly1305;
import com.ultracipher.core.api.UltraCipherEngine;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

/**
 * Streaming AEAD encryption for large files.
 *
 * Splits the stream into chunks (default 64KB), encrypts each with
 * a unique derived nonce, and writes a BLAKE3 hash at the end for
 * full-stream integrity verification.
 *
 * Format per chunk:
 *   [4 bytes: chunk length][encrypted chunk with auth tag]
 *
 * File format:
 *   [32 bytes: file header magic + version + algorithm]
 *   [12 bytes: base nonce]
 *   [N * (4 + chunkLen + 16) bytes: encrypted chunks]
 *   [32 bytes: BLAKE3 hash of all chunk ciphertexts]
 */
public final class StreamingEncryption {

    private static final byte[] MAGIC = { 0x55, 0x43, 0x49, 0x50, 0x48, 0x45, 0x52 }; // "UCIPHER"
    private static final int VERSION  = 1;
    private static final int DEFAULT_CHUNK_SIZE = 65536; // 64KB

    private final int chunkSize;
    private final UltraCipherEngine.Algorithm algorithm;

    public StreamingEncryption() {
        this(DEFAULT_CHUNK_SIZE, UltraCipherEngine.Algorithm.CHACHA20_POLY1305);
    }

    public StreamingEncryption(int chunkSize, UltraCipherEngine.Algorithm algorithm) {
        this.chunkSize = chunkSize;
        this.algorithm = algorithm;
    }

    /**
     * Encrypt an input stream to an output stream.
     *
     * @param in   plaintext input stream
     * @param out  ciphertext output stream
     * @param key  32-byte symmetric key
     * @param nonce 12-byte base nonce (unique per file!)
     */
    public void encrypt(InputStream in, OutputStream out, byte[] key, byte[] nonce) throws IOException {
        // Write header
        writeHeader(out, nonce);

        BLAKE3.hash(new byte[0]); // ensure class loaded
        byte[] integrityInput = new byte[0];

        long chunkIndex = 0;
        byte[] buf = new byte[chunkSize];
        int read;

        while ((read = readFull(in, buf)) > 0) {
            byte[] chunk = new byte[read];
            System.arraycopy(buf, 0, chunk, 0, read);

            // Derive per-chunk nonce: base nonce XOR chunk index
            byte[] chunkNonce = deriveChunkNonce(nonce, chunkIndex);

            // Encrypt chunk
            byte[] encChunk;
            if (algorithm == UltraCipherEngine.Algorithm.AES_256_GCM) {
                encChunk = AES256GCM.encrypt(chunk, longToBytes(chunkIndex), key, chunkNonce);
            } else {
                encChunk = ChaCha20Poly1305.encrypt(chunk, longToBytes(chunkIndex), key, chunkNonce);
            }

            // Write chunk length + encrypted chunk
            writeInt(out, encChunk.length);
            out.write(encChunk);

            // Accumulate for integrity hash
            integrityInput = appendBytes(integrityInput, encChunk);
            chunkIndex++;
        }

        // Write end marker
        writeInt(out, 0);

        // Write full-stream integrity hash
        byte[] streamHash = BLAKE3.keyedHash(integrityInput, padOrTruncate(key, 32));
        out.write(streamHash);
        out.flush();
    }

    /**
     * Decrypt an input stream to an output stream.
     *
     * @throws SecurityException if integrity check fails
     */
    public void decrypt(InputStream in, OutputStream out, byte[] key) throws IOException {
        // Read and verify header
        byte[] nonce = readHeader(in);

        long chunkIndex = 0;
        byte[] integrityInput = new byte[0];

        while (true) {
            int chunkLen = readInt(in);
            if (chunkLen == 0) break;

            byte[] encChunk = new byte[chunkLen];
            readExact(in, encChunk);

            byte[] chunkNonce = deriveChunkNonce(nonce, chunkIndex);

            byte[] plainChunk;
            if (algorithm == UltraCipherEngine.Algorithm.AES_256_GCM) {
                plainChunk = AES256GCM.decrypt(encChunk, longToBytes(chunkIndex), key, chunkNonce);
            } else {
                plainChunk = ChaCha20Poly1305.decrypt(encChunk, longToBytes(chunkIndex), key, chunkNonce);
            }

            out.write(plainChunk);
            integrityInput = appendBytes(integrityInput, encChunk);
            chunkIndex++;
        }

        // Verify stream integrity
        byte[] receivedHash = new byte[32];
        readExact(in, receivedHash);
        byte[] expectedHash = BLAKE3.keyedHash(integrityInput, padOrTruncate(key, 32));

        if (!constantTimeEquals(receivedHash, expectedHash)) {
            throw new SecurityException("Stream integrity check failed! File may be corrupted or tampered.");
        }

        out.flush();
    }

    // ─── Header ───────────────────────────────────────────────────────────────

    private void writeHeader(OutputStream out, byte[] nonce) throws IOException {
        out.write(MAGIC);                          // 7 bytes
        out.write(VERSION);                        // 1 byte
        out.write(algorithm == UltraCipherEngine.Algorithm.AES_256_GCM ? 1 : 2); // 1 byte
        out.write(new byte[23]);                   // 23 bytes reserved
        out.write(nonce);                          // 12 bytes
    }

    private byte[] readHeader(InputStream in) throws IOException {
        byte[] magic = new byte[7];
        readExact(in, magic);
        for (int i = 0; i < MAGIC.length; i++) {
            if (magic[i] != MAGIC[i]) throw new IOException("Invalid UltraCipher stream format");
        }
        int version = in.read();
        if (version != VERSION) throw new IOException("Unsupported version: " + version);
        in.read(); // algorithm (ignored - use what was configured)
        in.skip(23); // reserved
        byte[] nonce = new byte[12];
        readExact(in, nonce);
        return nonce;
    }

    // ─── Utility ──────────────────────────────────────────────────────────────

    private byte[] deriveChunkNonce(byte[] baseNonce, long index) {
        byte[] result = baseNonce.clone();
        // XOR chunk index into last 8 bytes of nonce
        for (int i = 0; i < 8; i++) {
            result[4 + i] ^= (byte)(index >> (i * 8));
        }
        return result;
    }

    private int readFull(InputStream in, byte[] buf) throws IOException {
        int total = 0;
        while (total < buf.length) {
            int r = in.read(buf, total, buf.length - total);
            if (r == -1) break;
            total += r;
        }
        return total;
    }

    private void readExact(InputStream in, byte[] buf) throws IOException {
        int total = 0;
        while (total < buf.length) {
            int r = in.read(buf, total, buf.length - total);
            if (r == -1) throw new IOException("Unexpected end of stream");
            total += r;
        }
    }

    private void writeInt(OutputStream out, int v) throws IOException {
        out.write((v >> 24) & 0xFF);
        out.write((v >> 16) & 0xFF);
        out.write((v >>  8) & 0xFF);
        out.write(v         & 0xFF);
    }

    private int readInt(InputStream in) throws IOException {
        int b0 = in.read(), b1 = in.read(), b2 = in.read(), b3 = in.read();
        if (b0 < 0) throw new IOException("EOF");
        return (b0 << 24) | (b1 << 16) | (b2 << 8) | b3;
    }

    private byte[] longToBytes(long v) {
        byte[] b = new byte[8];
        for (int i = 0; i < 8; i++) b[i] = (byte)(v >> (i * 8));
        return b;
    }

    private byte[] padOrTruncate(byte[] key, int len) {
        byte[] result = new byte[len];
        System.arraycopy(key, 0, result, 0, Math.min(key.length, len));
        return result;
    }

    private byte[] appendBytes(byte[] a, byte[] b) {
        byte[] result = new byte[a.length + b.length];
        System.arraycopy(a, 0, result, 0, a.length);
        System.arraycopy(b, 0, result, a.length, b.length);
        return result;
    }

    private boolean constantTimeEquals(byte[] a, byte[] b) {
        if (a.length != b.length) return false;
        int diff = 0;
        for (int i = 0; i < a.length; i++) diff |= (a[i] ^ b[i]);
        return diff == 0;
    }
}
