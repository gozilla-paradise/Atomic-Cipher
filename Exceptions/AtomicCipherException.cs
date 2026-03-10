namespace AtomicCipher.Exceptions;

public class AtomicCipherException : Exception
{
    public AtomicCipherException(string message) : base(message) { }
    public AtomicCipherException(string message, Exception innerException) : base(message, innerException) { }
}
