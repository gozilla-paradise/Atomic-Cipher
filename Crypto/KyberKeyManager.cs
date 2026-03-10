using System.IO;
using System.Security.Cryptography;
using System.Text;
using AtomicCipher.Exceptions;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Kems;
using Org.BouncyCastle.Crypto.Parameters;

namespace AtomicCipher.Crypto;

public static class KyberKeyManager
{
    private const string PublicKeyHeader = "-----BEGIN ATOMICCIPHER PUBLIC KEY-----";
    private const string PublicKeyFooter = "-----END ATOMICCIPHER PUBLIC KEY-----";
    private const string PrivateKeyHeader = "-----BEGIN ATOMICCIPHER PRIVATE KEY-----";
    private const string PrivateKeyFooter = "-----END ATOMICCIPHER PRIVATE KEY-----";

    public static AsymmetricCipherKeyPair GenerateKeyPair()
    {
        var keyGenParameters = new MLKemKeyGenerationParameters(
            SecureRandomProvider.GetBouncyCastleRandom(),
            MLKemParameters.ml_kem_768);

        var keyGen = new MLKemKeyPairGenerator();
        keyGen.Init(keyGenParameters);
        return keyGen.GenerateKeyPair();
    }

    public static (byte[] EncapsulatedKey, byte[] SharedSecret) Encapsulate(MLKemPublicKeyParameters publicKey)
    {
        var encapsulator = new MLKemEncapsulator(MLKemParameters.ml_kem_768);
        encapsulator.Init(publicKey);

        byte[] encapsulatedKey = new byte[encapsulator.EncapsulationLength];
        byte[] sharedSecret = new byte[encapsulator.SecretLength];

        encapsulator.Encapsulate(encapsulatedKey, 0, encapsulatedKey.Length,
            sharedSecret, 0, sharedSecret.Length);

        if (sharedSecret.Length != 32)
            throw new KeyException("Unexpected shared secret length from ML-KEM-768.");

        return (encapsulatedKey, sharedSecret);
    }

    public static byte[] Decapsulate(MLKemPrivateKeyParameters privateKey, byte[] encapsulatedKey)
    {
        var decapsulator = new MLKemDecapsulator(MLKemParameters.ml_kem_768);
        decapsulator.Init(privateKey);

        byte[] sharedSecret = new byte[decapsulator.SecretLength];
        decapsulator.Decapsulate(encapsulatedKey, 0, encapsulatedKey.Length,
            sharedSecret, 0, sharedSecret.Length);

        if (sharedSecret.Length != 32)
            throw new KeyException("Unexpected shared secret length from ML-KEM-768.");

        return sharedSecret;
    }

    public static string ExportPublicKey(MLKemPublicKeyParameters publicKey)
    {
        byte[] encoded = publicKey.GetEncoded();
        return FormatPem(encoded, PublicKeyHeader, PublicKeyFooter);
    }

    public static string ExportPrivateKey(MLKemPrivateKeyParameters privateKey)
    {
        byte[] encoded = privateKey.GetEncoded();
        return FormatPem(encoded, PrivateKeyHeader, PrivateKeyFooter);
    }

    public static MLKemPublicKeyParameters ImportPublicKey(string pem)
    {
        byte[] data = ParsePem(pem, PublicKeyHeader, PublicKeyFooter);
        try
        {
            return MLKemPublicKeyParameters.FromEncoding(MLKemParameters.ml_kem_768, data);
        }
        catch (Exception ex)
        {
            throw new KeyException("Invalid public key data.", ex);
        }
    }

    public static MLKemPrivateKeyParameters ImportPrivateKey(string pem)
    {
        byte[] data = ParsePem(pem, PrivateKeyHeader, PrivateKeyFooter);
        try
        {
            return MLKemPrivateKeyParameters.FromEncoding(MLKemParameters.ml_kem_768, data);
        }
        catch (Exception ex)
        {
            throw new KeyException("Invalid private key data.", ex);
        }
    }

    public static async Task SavePublicKeyAsync(MLKemPublicKeyParameters publicKey, string filePath)
    {
        string pem = ExportPublicKey(publicKey);
        await File.WriteAllTextAsync(filePath, pem, Encoding.UTF8);
    }

    public static async Task SavePrivateKeyAsync(MLKemPrivateKeyParameters privateKey, string filePath)
    {
        string pem = ExportPrivateKey(privateKey);
        await File.WriteAllTextAsync(filePath, pem, Encoding.UTF8);
    }

    public static async Task<MLKemPublicKeyParameters> LoadPublicKeyAsync(string filePath)
    {
        string pem = await File.ReadAllTextAsync(filePath, Encoding.UTF8);
        return ImportPublicKey(pem);
    }

    public static async Task<MLKemPrivateKeyParameters> LoadPrivateKeyAsync(string filePath)
    {
        string pem = await File.ReadAllTextAsync(filePath, Encoding.UTF8);
        return ImportPrivateKey(pem);
    }

    private static string FormatPem(byte[] data, string header, string footer)
    {
        var sb = new StringBuilder();
        sb.AppendLine(header);

        string base64 = Convert.ToBase64String(data);
        for (int i = 0; i < base64.Length; i += 64)
        {
            int len = Math.Min(64, base64.Length - i);
            sb.AppendLine(base64.Substring(i, len));
        }

        sb.AppendLine(footer);
        return sb.ToString();
    }

    private static byte[] ParsePem(string pem, string expectedHeader, string expectedFooter)
    {
        string trimmed = pem.Trim();
        if (!trimmed.StartsWith(expectedHeader) || !trimmed.EndsWith(expectedFooter))
            throw new KeyException("Invalid key format: missing or incorrect PEM header/footer.");

        string base64 = trimmed
            .Replace(expectedHeader, "")
            .Replace(expectedFooter, "")
            .Replace("\r", "")
            .Replace("\n", "")
            .Trim();

        try
        {
            return Convert.FromBase64String(base64);
        }
        catch (FormatException ex)
        {
            throw new KeyException("Invalid key format: corrupted base64 data.", ex);
        }
    }
}
