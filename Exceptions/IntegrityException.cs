namespace AtomicCipher.Exceptions;

public class IntegrityException : AtomicCipherException
{
    public IntegrityException(string message) : base(message) { }
    public IntegrityException(string message, Exception innerException) : base(message, innerException) { }
}
