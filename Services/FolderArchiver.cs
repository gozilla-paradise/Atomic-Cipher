using System.IO;
using System.IO.Compression;

namespace AtomicCipher.Services;

public static class FolderArchiver
{
    public static SecureTempFile ArchiveFolder(string folderPath)
    {
        if (!Directory.Exists(folderPath))
            throw new DirectoryNotFoundException($"Folder not found: {folderPath}");

        var tempFile = new SecureTempFile(".zip", createFile: false);

        try
        {
            ZipFile.CreateFromDirectory(folderPath, tempFile.FilePath,
                CompressionLevel.Optimal, includeBaseDirectory: false);
        }
        catch
        {
            tempFile.Dispose();
            throw;
        }

        return tempFile;
    }

    public static SecureTempFile ArchiveFile(string filePath)
    {
        if (!File.Exists(filePath))
            throw new FileNotFoundException($"File not found: {filePath}", filePath);

        var tempFile = new SecureTempFile(".zip", createFile: false);

        try
        {
            using var archive = ZipFile.Open(tempFile.FilePath, ZipArchiveMode.Create);
            archive.CreateEntryFromFile(filePath, Path.GetFileName(filePath), CompressionLevel.Optimal);
        }
        catch
        {
            tempFile.Dispose();
            throw;
        }

        return tempFile;
    }

    public static void ExtractSingleFile(string zipPath, string outputFilePath)
    {
        using var archive = ZipFile.OpenRead(zipPath);
        var entry = archive.Entries[0];
        entry.ExtractToFile(outputFilePath, overwrite: true);
    }

    public static void ExtractArchive(string zipPath, string outputFolderPath)
    {
        Directory.CreateDirectory(outputFolderPath);
        ZipFile.ExtractToDirectory(zipPath, outputFolderPath, overwriteFiles: true);
    }

    public static void ExtractArchive(Stream zipStream, string outputFolderPath)
    {
        Directory.CreateDirectory(outputFolderPath);
        using var archive = new ZipArchive(zipStream, ZipArchiveMode.Read);
        archive.ExtractToDirectory(outputFolderPath, overwriteFiles: true);
    }
}
