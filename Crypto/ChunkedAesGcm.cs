using System.Buffers.Binary;
using System.Security.Cryptography;
using AtomicCipher.Exceptions;

namespace AtomicCipher.Crypto;

public static class ChunkedAesGcm
{
    public const int ChunkSize = 65536; // 64 KiB
    public const int NonceSize = 12;
    public const int TagSize = 16;
    public const int KeySize = 32;

    public static (byte[] Ciphertext, byte[] Tag) EncryptChunk(
        byte[] key, byte[] baseNonce, uint chunkIndex, ReadOnlySpan<byte> plaintext)
    {
        byte[] nonce = DeriveNonce(baseNonce, chunkIndex);
        byte[] ciphertext = new byte[plaintext.Length];
        byte[] tag = new byte[TagSize];

        using var aes = new AesGcm(key, TagSize);
        aes.Encrypt(nonce, plaintext, ciphertext, tag);

        return (ciphertext, tag);
    }

    public static byte[] DecryptChunk(
        byte[] key, byte[] baseNonce, uint chunkIndex, ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> tag)
    {
        byte[] nonce = DeriveNonce(baseNonce, chunkIndex);
        byte[] plaintext = new byte[ciphertext.Length];

        try
        {
            using var aes = new AesGcm(key, TagSize);
            aes.Decrypt(nonce, ciphertext, tag, plaintext);
        }
        catch (CryptographicException ex)
        {
            throw new IntegrityException("Chunk authentication failed. Data may be corrupted or tampered with.", ex);
        }

        return plaintext;
    }

    private static byte[] DeriveNonce(byte[] baseNonce, uint chunkIndex)
    {
        byte[] nonce = new byte[NonceSize];
        Array.Copy(baseNonce, nonce, NonceSize);

        // XOR chunk index (big-endian) into the last 4 bytes of the nonce
        byte[] indexBytes = new byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(indexBytes, chunkIndex);

        nonce[8] ^= indexBytes[0];
        nonce[9] ^= indexBytes[1];
        nonce[10] ^= indexBytes[2];
        nonce[11] ^= indexBytes[3];

        return nonce;
    }
}
