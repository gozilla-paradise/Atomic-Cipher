using System.Security.Cryptography;
using Org.BouncyCastle.Security;

namespace AtomicCipher.Crypto;

public static class SecureRandomProvider
{
    private static readonly SecureRandom BouncyCastleRandom = new();

    public static byte[] GenerateBytes(int count)
    {
        byte[] buffer = new byte[count];
        RandomNumberGenerator.Fill(buffer);
        return buffer;
    }

    public static SecureRandom GetBouncyCastleRandom() => BouncyCastleRandom;
}
