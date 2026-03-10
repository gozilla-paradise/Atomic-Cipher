using System.IO;
using System.Security.Cryptography;
using System.Text;
using AtomicCipher.Exceptions;

namespace AtomicCipher.FileFormat;

public enum ContentType : byte
{
    SingleFile = 0x00,
    FolderArchive = 0x01
}

public enum KemAlgorithm : ushort
{
    MlKem768 = 1
}

public enum SymmetricAlgorithm : ushort
{
    Aes256Gcm = 1
}

public enum KeyDerivationMode : byte
{
    Kem = 0x00,
    Passphrase = 0x01
}

public class AtomicFileHeader
{
    public static readonly byte[] Magic = { 0x41, 0x43, 0x46, 0x00 }; // "ACF\0"
    public const ushort CurrentVersion = 2;

    public ushort Version { get; set; } = CurrentVersion;
    public ContentType ContentType { get; set; }
    public KemAlgorithm KemAlgorithm { get; set; } = KemAlgorithm.MlKem768;
    public SymmetricAlgorithm SymmetricAlgorithm { get; set; } = SymmetricAlgorithm.Aes256Gcm;
    public KeyDerivationMode KeyDerivationMode { get; set; } = KeyDerivationMode.Kem;
    public string OriginalName { get; set; } = string.Empty;
    public byte[] EncryptedName { get; set; } = Array.Empty<byte>();
    public byte[] EncapsulatedKey { get; set; } = Array.Empty<byte>();
    public uint ChunkSize { get; set; } = Crypto.ChunkedAesGcm.ChunkSize;
    public ulong OriginalPayloadSize { get; set; }
    public byte[] BaseNonce { get; set; } = new byte[Crypto.ChunkedAesGcm.NonceSize];
    public uint ChunkCount { get; set; }

    private const int NameNonceSize = 12;
    private const int NameTagSize = 16;

    public void WriteTo(BinaryWriter writer, byte[] sharedSecret)
    {
        byte[] encryptedName = EncryptName(OriginalName, sharedSecret);

        writer.Write(Magic);
        writer.Write(Version);
        writer.Write((byte)ContentType);
        writer.Write((ushort)KemAlgorithm);
        writer.Write((ushort)SymmetricAlgorithm);
        writer.Write((byte)KeyDerivationMode);
        writer.Write((ushort)encryptedName.Length);
        writer.Write(encryptedName);
        writer.Write((uint)EncapsulatedKey.Length);
        writer.Write(EncapsulatedKey);
        writer.Write(ChunkSize);
        writer.Write(OriginalPayloadSize);
        writer.Write(BaseNonce);
        writer.Write(ChunkCount);
    }

    public static AtomicFileHeader ReadFrom(BinaryReader reader)
    {
        byte[] magic = reader.ReadBytes(4);
        if (!magic.AsSpan().SequenceEqual(Magic))
            throw new AtomicCipherException("Invalid file: missing ACF magic bytes.");

        var header = new AtomicFileHeader
        {
            Version = reader.ReadUInt16()
        };

        if (header.Version < 1 || header.Version > CurrentVersion)
            throw new AtomicCipherException($"Unsupported file version: {header.Version}.");

        header.ContentType = (ContentType)reader.ReadByte();
        header.KemAlgorithm = (KemAlgorithm)reader.ReadUInt16();
        header.SymmetricAlgorithm = (SymmetricAlgorithm)reader.ReadUInt16();

        // Version 2+ includes KeyDerivationMode byte; version 1 defaults to KEM
        if (header.Version >= 2)
            header.KeyDerivationMode = (KeyDerivationMode)reader.ReadByte();
        else
            header.KeyDerivationMode = KeyDerivationMode.Kem;

        ushort nameLen = reader.ReadUInt16();
        header.EncryptedName = reader.ReadBytes(nameLen);

        uint encKeyLen = reader.ReadUInt32();
        header.EncapsulatedKey = reader.ReadBytes((int)encKeyLen);

        header.ChunkSize = reader.ReadUInt32();
        header.OriginalPayloadSize = reader.ReadUInt64();
        header.BaseNonce = reader.ReadBytes(Crypto.ChunkedAesGcm.NonceSize);
        header.ChunkCount = reader.ReadUInt32();

        return header;
    }

    public void DecryptOriginalName(byte[] sharedSecret)
    {
        if (EncryptedName.Length < NameNonceSize + NameTagSize)
            throw new AtomicCipherException("Encrypted name data is too short.");

        byte[] nonce = EncryptedName[..NameNonceSize];
        byte[] tag = EncryptedName[NameNonceSize..(NameNonceSize + NameTagSize)];
        byte[] ciphertext = EncryptedName[(NameNonceSize + NameTagSize)..];

        byte[] plaintext = new byte[ciphertext.Length];
        using var aes = new AesGcm(sharedSecret, NameTagSize);
        aes.Decrypt(nonce, ciphertext, tag, plaintext);

        OriginalName = Encoding.UTF8.GetString(plaintext);
    }

    private static byte[] EncryptName(string name, byte[] sharedSecret)
    {
        byte[] plaintext = Encoding.UTF8.GetBytes(name);
        byte[] nonce = new byte[NameNonceSize];
        RandomNumberGenerator.Fill(nonce);
        byte[] ciphertext = new byte[plaintext.Length];
        byte[] tag = new byte[NameTagSize];

        using var aes = new AesGcm(sharedSecret, NameTagSize);
        aes.Encrypt(nonce, plaintext, ciphertext, tag);

        // Format: nonce (12) + tag (16) + ciphertext
        byte[] result = new byte[NameNonceSize + NameTagSize + ciphertext.Length];
        nonce.CopyTo(result, 0);
        tag.CopyTo(result, NameNonceSize);
        ciphertext.CopyTo(result, NameNonceSize + NameTagSize);
        return result;
    }
}
