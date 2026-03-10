using System.IO;
using System.Security.Cryptography;
using AtomicCipher.Crypto;

namespace AtomicCipher.FileFormat;

public static class AtomicFileWriter
{
    public static async Task WriteEncryptedFileAsync(
        Stream sourceStream,
        Stream outputStream,
        AtomicFileHeader header,
        byte[] sharedSecret,
        IProgress<long>? progress = null,
        CancellationToken cancellationToken = default)
    {
        // Write header
        using var writer = new BinaryWriter(outputStream, System.Text.Encoding.UTF8, leaveOpen: true);
        header.WriteTo(writer, sharedSecret);
        writer.Flush();

        // Start HMAC computation over everything written so far
        long hmacStartPosition = 0;

        // We'll collect all bytes for HMAC at the end by re-reading
        // For streaming, we track the position before chunks

        // Encrypt and write chunks
        byte[] buffer = new byte[header.ChunkSize];
        uint chunkIndex = 0;
        long totalBytesRead = 0;

        while (true)
        {
            cancellationToken.ThrowIfCancellationRequested();

            int bytesRead = await ReadFullBufferAsync(sourceStream, buffer, cancellationToken);
            if (bytesRead == 0)
                break;

            ReadOnlySpan<byte> plaintext = buffer.AsSpan(0, bytesRead);
            var (ciphertext, tag) = ChunkedAesGcm.EncryptChunk(sharedSecret, header.BaseNonce, chunkIndex, plaintext);

            writer.Write((uint)ciphertext.Length);
            writer.Write(ciphertext);
            writer.Write(tag);
            writer.Flush();

            totalBytesRead += bytesRead;
            chunkIndex++;
            progress?.Report(totalBytesRead);
        }

        // Now compute HMAC-SHA256 over all preceding bytes
        writer.Flush();
        outputStream.Flush();

        byte[] hmac = await ComputeHmacAsync(outputStream, sharedSecret, hmacStartPosition, cancellationToken);
        writer.Write(hmac);
        writer.Flush();
    }

    private static async Task<byte[]> ComputeHmacAsync(
        Stream stream, byte[] key, long startPosition, CancellationToken cancellationToken)
    {
        long endPosition = stream.Position;
        stream.Position = startPosition;

        using var hmac = new HMACSHA256(key);
        byte[] buffer = new byte[81920];
        long remaining = endPosition - startPosition;

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
        stream.Position = endPosition;
        return hmac.Hash!;
    }

    private static async Task<int> ReadFullBufferAsync(
        Stream stream, byte[] buffer, CancellationToken cancellationToken)
    {
        int totalRead = 0;
        while (totalRead < buffer.Length)
        {
            int bytesRead = await stream.ReadAsync(
                buffer.AsMemory(totalRead, buffer.Length - totalRead), cancellationToken);
            if (bytesRead == 0)
                break;
            totalRead += bytesRead;
        }
        return totalRead;
    }
}
