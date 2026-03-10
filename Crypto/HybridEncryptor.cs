using System.IO;
using System.Security.Cryptography;
using AtomicCipher.FileFormat;
using AtomicCipher.Services;
using Org.BouncyCastle.Crypto.Parameters;

namespace AtomicCipher.Crypto;

public static class HybridEncryptor
{
    public static async Task EncryptFileAsync(
        string sourceFilePath,
        string outputFilePath,
        MLKemPublicKeyParameters publicKey,
        IProgress<long>? progress = null,
        CancellationToken cancellationToken = default)
    {
        using var tempFile = FolderArchiver.ArchiveFile(sourceFilePath);

        var (encapsulatedKey, sharedSecret) = KyberKeyManager.Encapsulate(publicKey);
        try
        {
            var fileInfo = new FileInfo(tempFile.FilePath);
            ulong payloadSize = (ulong)fileInfo.Length;
            uint chunkCount = payloadSize == 0 ? 0
                : (uint)((payloadSize + ChunkedAesGcm.ChunkSize - 1) / ChunkedAesGcm.ChunkSize);

            var header = new AtomicFileHeader
            {
                ContentType = ContentType.SingleFile,
                OriginalName = Path.GetFileName(sourceFilePath),
                EncapsulatedKey = encapsulatedKey,
                OriginalPayloadSize = payloadSize,
                BaseNonce = SecureRandomProvider.GenerateBytes(ChunkedAesGcm.NonceSize),
                ChunkCount = chunkCount
            };

            using var sourceStream = tempFile.OpenRead();
            using var outputStream = new FileStream(outputFilePath, FileMode.Create, FileAccess.ReadWrite, FileShare.None);

            await AtomicFileWriter.WriteEncryptedFileAsync(
                sourceStream, outputStream, header, sharedSecret, progress, cancellationToken);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(sharedSecret);
        }
    }

    public static async Task EncryptFolderAsync(
        string sourceFolderPath,
        string outputFilePath,
        MLKemPublicKeyParameters publicKey,
        IProgress<long>? progress = null,
        CancellationToken cancellationToken = default)
    {
        using var tempFile = FolderArchiver.ArchiveFolder(sourceFolderPath);

        var (encapsulatedKey, sharedSecret) = KyberKeyManager.Encapsulate(publicKey);
        try
        {
            var fileInfo = new FileInfo(tempFile.FilePath);
            ulong payloadSize = (ulong)fileInfo.Length;
            uint chunkCount = payloadSize == 0 ? 0
                : (uint)((payloadSize + ChunkedAesGcm.ChunkSize - 1) / ChunkedAesGcm.ChunkSize);

            var header = new AtomicFileHeader
            {
                ContentType = ContentType.FolderArchive,
                OriginalName = Path.GetFileName(sourceFolderPath),
                EncapsulatedKey = encapsulatedKey,
                OriginalPayloadSize = payloadSize,
                BaseNonce = SecureRandomProvider.GenerateBytes(ChunkedAesGcm.NonceSize),
                ChunkCount = chunkCount
            };

            using var sourceStream = tempFile.OpenRead();
            using var outputStream = new FileStream(outputFilePath, FileMode.Create, FileAccess.ReadWrite, FileShare.None);

            await AtomicFileWriter.WriteEncryptedFileAsync(
                sourceStream, outputStream, header, sharedSecret, progress, cancellationToken);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(sharedSecret);
        }
    }
}
