namespace AtomicCipher.Exceptions;

public class KeyException : AtomicCipherException
{
    public KeyException(string message) : base(message) { }
    public KeyException(string message, Exception innerException) : base(message, innerException) { }
}
