using System.IO;
using System.Security.Cryptography;
using AtomicCipher.FileFormat;
using AtomicCipher.Services;

namespace AtomicCipher.Crypto;

public static class PassphraseEncryptor
{
    public static async Task EncryptFileAsync(
        string sourceFilePath,
        string outputFilePath,
        string passphrase,
        IProgress<long>? progress = null,
        CancellationToken cancellationToken = default)
    {
        using var tempFile = FolderArchiver.ArchiveFile(sourceFilePath);

        byte[] salt = PassphraseKeyDeriver.GenerateSalt();
        byte[] kdfBlob = PassphraseKeyDeriver.SerializeKdfParams(
            salt, PassphraseKeyDeriver.DefaultMemoryCostKiB,
            PassphraseKeyDeriver.DefaultIterations, PassphraseKeyDeriver.DefaultParallelism);

        byte[] sharedSecret = PassphraseKeyDeriver.DeriveKey(passphrase, salt);
        try
        {
            var fileInfo = new FileInfo(tempFile.FilePath);
            ulong payloadSize = (ulong)fileInfo.Length;
            uint chunkCount = payloadSize == 0 ? 0
                : (uint)((payloadSize + ChunkedAesGcm.ChunkSize - 1) / ChunkedAesGcm.ChunkSize);

            var header = new AtomicFileHeader
            {
                ContentType = ContentType.SingleFile,
                KeyDerivationMode = KeyDerivationMode.Passphrase,
                OriginalName = Path.GetFileName(sourceFilePath),
                EncapsulatedKey = kdfBlob,
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
        string passphrase,
        IProgress<long>? progress = null,
        CancellationToken cancellationToken = default)
    {
        using var tempFile = FolderArchiver.ArchiveFolder(sourceFolderPath);

        byte[] salt = PassphraseKeyDeriver.GenerateSalt();
        byte[] kdfBlob = PassphraseKeyDeriver.SerializeKdfParams(
            salt, PassphraseKeyDeriver.DefaultMemoryCostKiB,
            PassphraseKeyDeriver.DefaultIterations, PassphraseKeyDeriver.DefaultParallelism);

        byte[] sharedSecret = PassphraseKeyDeriver.DeriveKey(passphrase, salt);
        try
        {
            var fileInfo = new FileInfo(tempFile.FilePath);
            ulong payloadSize = (ulong)fileInfo.Length;
            uint chunkCount = payloadSize == 0 ? 0
                : (uint)((payloadSize + ChunkedAesGcm.ChunkSize - 1) / ChunkedAesGcm.ChunkSize);

            var header = new AtomicFileHeader
            {
                ContentType = ContentType.FolderArchive,
                KeyDerivationMode = KeyDerivationMode.Passphrase,
                OriginalName = Path.GetFileName(sourceFolderPath),
                EncapsulatedKey = kdfBlob,
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
