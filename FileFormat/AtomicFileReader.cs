using System.IO;
using System.Security.Cryptography;
using AtomicCipher.Crypto;
using AtomicCipher.Exceptions;

namespace AtomicCipher.FileFormat;

public static class AtomicFileReader
{
    public static AtomicFileHeader ReadHeader(Stream stream)
    {
        using var reader = new BinaryReader(stream, System.Text.Encoding.UTF8, leaveOpen: true);
        return AtomicFileHeader.ReadFrom(reader);
    }

    public static async Task VerifyHmacAsync(
        Stream stream, byte[] sharedSecret, CancellationToken cancellationToken = default)
    {
        const int hmacSize = 32;

        if (stream.Length < hmacSize)
            throw new IntegrityException("File is too small to contain a valid HMAC.");

        // Read stored HMAC from end of file
        stream.Position = stream.Length - hmacSize;
        byte[] storedHmac = new byte[hmacSize];
        await stream.ReadExactlyAsync(storedHmac, cancellationToken);

        // Compute HMAC over everything except the last 32 bytes
        stream.Position = 0;
        long dataLength = stream.Length - hmacSize;

        using var hmac = new HMACSHA256(sharedSecret);
        byte[] buffer = new byte[81920];
        long remaining = dataLength;

        while (remaining > 0)
        {
            cancellationToken.ThrowIfCancellationRequested();
            int toRead = (int)Math.Min(buffer.Length, remaining);
            int bytesRead = await stream.ReadAsync(buffer.AsMemory(0, toRead), cancellationToken);
            if (bytesRead == 0) break;
            hmac.TransformBlock(buffer, 0, bytesRead, null, 0);
            remaining -= bytesRead;
        }

        hmac.TransformFinalBlock(Array.Empty<byte>(), 0, 0);
        byte[] computedHmac = hmac.Hash!;

        if (!CryptographicOperations.FixedTimeEquals(storedHmac, computedHmac))
            throw new IntegrityException("File integrity check failed. The file may have been tampered with or the wrong key was used.");
    }

    public static async Task DecryptToStreamAsync(
        Stream inputStream,
        Stream outputStream,
        AtomicFileHeader header,
        byte[] sharedSecret,
        IProgress<long>? progress = null,
        CancellationToken cancellationToken = default)
    {
        using var reader = new BinaryReader(inputStream, System.Text.Encoding.UTF8, leaveOpen: true);
        long totalDecrypted = 0;

        for (uint i = 0; i < header.ChunkCount; i++)
        {
            cancellationToken.ThrowIfCancellationRequested();

            uint ciphertextLen = reader.ReadUInt32();
            byte[] ciphertext = reader.ReadBytes((int)ciphertextLen);
            byte[] tag = reader.ReadBytes(ChunkedAesGcm.TagSize);

            byte[] plaintext = ChunkedAesGcm.DecryptChunk(
                sharedSecret, header.BaseNonce, i, ciphertext, tag);

            await outputStream.WriteAsync(plaintext, cancellationToken);
            totalDecrypted += plaintext.Length;
            progress?.Report(totalDecrypted);
        }

        if ((ulong)totalDecrypted != header.OriginalPayloadSize)
            throw new IntegrityException(
                $"Decrypted size mismatch. Expected {header.OriginalPayloadSize} bytes but got {totalDecrypted}.");
    }
}
