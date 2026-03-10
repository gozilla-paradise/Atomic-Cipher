using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;

namespace AtomicCipher.Crypto;

public static class PassphraseKeyDeriver
{
    public const int SaltSize = 32;
    public const int KdfBlobSize = 44;
    public const int DefaultMemoryCostKiB = 65536; // 64 MiB
    public const int DefaultIterations = 3;
    public const int DefaultParallelism = 4;
    private const int DerivedKeyLength = 32;

    public static byte[] DeriveKey(string passphrase, byte[] salt,
        int memoryCostKiB = DefaultMemoryCostKiB,
        int iterations = DefaultIterations,
        int parallelism = DefaultParallelism)
    {
        byte[] passphraseBytes = Encoding.UTF8.GetBytes(passphrase);
        try
        {
            var parameters = new Argon2Parameters.Builder(Argon2Parameters.Argon2id)
                .WithSalt(salt)
                .WithMemoryAsKB(memoryCostKiB)
                .WithIterations(iterations)
                .WithParallelism(parallelism)
                .Build();

            var generator = new Argon2BytesGenerator();
            generator.Init(parameters);

            byte[] key = new byte[DerivedKeyLength];
            generator.GenerateBytes(passphraseBytes, key);
            return key;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(passphraseBytes);
        }
    }

    public static byte[] GenerateSalt()
    {
        return SecureRandomProvider.GenerateBytes(SaltSize);
    }

    public static byte[] SerializeKdfParams(byte[] salt, int memoryCostKiB, int iterations, int parallelism)
    {
        byte[] blob = new byte[KdfBlobSize];
        salt.CopyTo(blob, 0);
        BinaryPrimitives.WriteUInt32LittleEndian(blob.AsSpan(32), (uint)memoryCostKiB);
        BinaryPrimitives.WriteUInt32LittleEndian(blob.AsSpan(36), (uint)iterations);
        BinaryPrimitives.WriteUInt32LittleEndian(blob.AsSpan(40), (uint)parallelism);
        return blob;
    }

    public static (byte[] Salt, int MemoryCostKiB, int Iterations, int Parallelism) DeserializeKdfParams(byte[] blob)
    {
        if (blob.Length != KdfBlobSize)
            throw new Exceptions.AtomicCipherException($"Invalid KDF params blob size: expected {KdfBlobSize}, got {blob.Length}.");

        byte[] salt = blob[..SaltSize];
        int memoryCostKiB = (int)BinaryPrimitives.ReadUInt32LittleEndian(blob.AsSpan(32));
        int iterations = (int)BinaryPrimitives.ReadUInt32LittleEndian(blob.AsSpan(36));
        int parallelism = (int)BinaryPrimitives.ReadUInt32LittleEndian(blob.AsSpan(40));

        return (salt, memoryCostKiB, iterations, parallelism);
    }
}
