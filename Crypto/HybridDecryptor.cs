using System.IO;
using System.Security.Cryptography;
using AtomicCipher.FileFormat;
using AtomicCipher.Services;
using Org.BouncyCastle.Crypto.Parameters;

namespace AtomicCipher.Crypto;

public static class HybridDecryptor
{
    public static KeyDerivationMode DetectMode(string filePath)
    {
        using var stream = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.Read);
        var header = AtomicFileReader.ReadHeader(stream);
        return header.KeyDerivationMode;
    }

    public static async Task<string> DecryptFileAsync(
        string encryptedFilePath,
        string outputDirectory,
        MLKemPrivateKeyParameters privateKey,
        IProgress<long>? progress = null,
        CancellationToken cancellationToken = default)
    {
        using var inputStream = new FileStream(encryptedFilePath, FileMode.Open, FileAccess.Read, FileShare.Read);

        var header = AtomicFileReader.ReadHeader(inputStream);
        long chunksStartPosition = inputStream.Position;

        byte[] sharedSecret = KyberKeyManager.Decapsulate(privateKey, header.EncapsulatedKey);
        try
        {
            return await DecryptWithSecretAsync(inputStream, header, chunksStartPosition, sharedSecret, outputDirectory, progress, cancellationToken);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(sharedSecret);
        }
    }

    public static async Task<string> DecryptFileAsync(
        string encryptedFilePath,
        string outputDirectory,
        string passphrase,
        IProgress<long>? progress = null,
        CancellationToken cancellationToken = default)
    {
        using var inputStream = new FileStream(encryptedFilePath, FileMode.Open, FileAccess.Read, FileShare.Read);

        var header = AtomicFileReader.ReadHeader(inputStream);
        long chunksStartPosition = inputStream.Position;

        if (header.KeyDerivationMode != KeyDerivationMode.Passphrase)
            throw new Exceptions.AtomicCipherException("This file was not encrypted with a passphrase. Use a private key to decrypt.");

        var (salt, memoryCostKiB, iterations, parallelism) = PassphraseKeyDeriver.DeserializeKdfParams(header.EncapsulatedKey);
        byte[] sharedSecret = PassphraseKeyDeriver.DeriveKey(passphrase, salt, memoryCostKiB, iterations, parallelism);
        try
        {
            return await DecryptWithSecretAsync(inputStream, header, chunksStartPosition, sharedSecret, outputDirectory, progress, cancellationToken);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(sharedSecret);
        }
    }

    private static async Task<string> DecryptWithSecretAsync(
        FileStream inputStream,
        AtomicFileHeader header,
        long chunksStartPosition,
        byte[] sharedSecret,
        string outputDirectory,
        IProgress<long>? progress,
        CancellationToken cancellationToken)
    {
        await AtomicFileReader.VerifyHmacAsync(inputStream, sharedSecret, cancellationToken);

        header.DecryptOriginalName(sharedSecret);

        inputStream.Position = chunksStartPosition;

        string outputPath;

        if (header.ContentType == ContentType.FolderArchive)
        {
            outputPath = Path.Combine(outputDirectory, header.OriginalName);
            using var tempFile = new SecureTempFile(".zip");

            using (var tempStream = tempFile.OpenWrite())
            {
                await AtomicFileReader.DecryptToStreamAsync(
                    inputStream, tempStream, header, sharedSecret, progress, cancellationToken);
            }

            FolderArchiver.ExtractArchive(tempFile.FilePath, outputPath);
        }
        else
        {
            outputPath = Path.Combine(outputDirectory, header.OriginalName);
            using var tempFile = new SecureTempFile(".zip");

            using (var tempStream = tempFile.OpenWrite())
            {
                await AtomicFileReader.DecryptToStreamAsync(
                    inputStream, tempStream, header, sharedSecret, progress, cancellationToken);
            }

            FolderArchiver.ExtractSingleFile(tempFile.FilePath, outputPath);
        }

        return outputPath;
    }
}
