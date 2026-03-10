using System.IO;

namespace AtomicCipher.Services;

public sealed class SecureTempFile : IDisposable
{
    public string FilePath { get; }
    private bool _disposed;

    public SecureTempFile(string? extension = null, bool createFile = true)
    {
        string tempDir = Path.GetTempPath();
        string fileName = $"ac_{Guid.NewGuid():N}{extension ?? ".tmp"}";
        FilePath = Path.Combine(tempDir, fileName);

        if (createFile)
        {
            using var fs = new FileStream(FilePath, FileMode.CreateNew, FileAccess.Write, FileShare.None);
            File.SetAttributes(FilePath, FileAttributes.Temporary);
        }
    }

    public FileStream OpenWrite()
    {
        return new FileStream(FilePath, FileMode.Open, FileAccess.Write, FileShare.None);
    }

    public FileStream OpenRead()
    {
        return new FileStream(FilePath, FileMode.Open, FileAccess.Read, FileShare.Read);
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;

        try
        {
            if (!File.Exists(FilePath)) return;

            // Overwrite file contents with zeros
            var fileInfo = new FileInfo(FilePath);
            long length = fileInfo.Length;

            if (length > 0)
            {
                using var fs = new FileStream(FilePath, FileMode.Open, FileAccess.Write, FileShare.None);
                byte[] zeros = new byte[(int)Math.Min(81920, length)];
                long remaining = length;
                while (remaining > 0)
                {
                    int toWrite = (int)Math.Min(zeros.Length, remaining);
                    fs.Write(zeros, 0, toWrite);
                    remaining -= toWrite;
                }
                fs.Flush(true);
            }

            File.Delete(FilePath);
        }
        catch
        {
            // Best-effort cleanup — don't throw from Dispose
        }
    }
}
