using System.Runtime.InteropServices;
using Microsoft.Win32;

namespace AtomicCipher.Services;

public static partial class ContextMenuInstaller
{
    private const string FileEncryptKeyPath = @"Software\Classes\*\shell\AtomicCipherEncrypt";
    private const string DirEncryptKeyPath = @"Software\Classes\Directory\shell\AtomicCipherEncrypt";
    private const string AcfExtKeyPath = @"Software\Classes\.acf";
    private const string AcfTypeKeyPath = @"Software\Classes\AtomicCipher.EncryptedFile";

    [LibraryImport("shell32.dll")]
    private static partial void SHChangeNotify(int wEventId, int uFlags, nint dwItem1, nint dwItem2);

    private const int SHCNE_ASSOCCHANGED = 0x08000000;
    private const int SHCNF_IDLIST = 0x0000;

    public static void Install(string exePath)
    {
        string quotedExe = $"\"{exePath}\"";

        using (var key = Registry.CurrentUser.CreateSubKey(FileEncryptKeyPath))
        {
            key.SetValue(null, "Encrypt with AtomicCipher");
            key.SetValue("Icon", $"{exePath},0");
        }
        using (var key = Registry.CurrentUser.CreateSubKey(FileEncryptKeyPath + @"\command"))
        {
            key.SetValue(null, $"{quotedExe} --encrypt \"%1\"");
        }

        using (var key = Registry.CurrentUser.CreateSubKey(DirEncryptKeyPath))
        {
            key.SetValue(null, "Encrypt with AtomicCipher");
            key.SetValue("Icon", $"{exePath},0");
        }
        using (var key = Registry.CurrentUser.CreateSubKey(DirEncryptKeyPath + @"\command"))
        {
            key.SetValue(null, $"{quotedExe} --encrypt \"%1\"");
        }

        using (var key = Registry.CurrentUser.CreateSubKey(AcfExtKeyPath))
        {
            key.SetValue(null, "AtomicCipher.EncryptedFile");
        }

        using (var key = Registry.CurrentUser.CreateSubKey(AcfTypeKeyPath))
        {
            key.SetValue(null, "AtomicCipher Encrypted File");
        }
        using (var key = Registry.CurrentUser.CreateSubKey(AcfTypeKeyPath + @"\shell\open\command"))
        {
            key.SetValue(null, $"{quotedExe} --decrypt \"%1\"");
        }
        using (var key = Registry.CurrentUser.CreateSubKey(AcfTypeKeyPath + @"\shell\AtomicCipherDecrypt"))
        {
            key.SetValue(null, "Decrypt with AtomicCipher");
        }
        using (var key = Registry.CurrentUser.CreateSubKey(AcfTypeKeyPath + @"\shell\AtomicCipherDecrypt\command"))
        {
            key.SetValue(null, $"{quotedExe} --decrypt \"%1\"");
        }

        SHChangeNotify(SHCNE_ASSOCCHANGED, SHCNF_IDLIST, 0, 0);
    }

    public static void Uninstall()
    {
        DeleteSubKeyTree(FileEncryptKeyPath);
        DeleteSubKeyTree(DirEncryptKeyPath);
        DeleteSubKeyTree(AcfExtKeyPath);
        DeleteSubKeyTree(AcfTypeKeyPath);

        SHChangeNotify(SHCNE_ASSOCCHANGED, SHCNF_IDLIST, 0, 0);
    }

    public static bool IsInstalled()
    {
        using var key = Registry.CurrentUser.OpenSubKey(FileEncryptKeyPath);
        return key != null;
    }

    private static void DeleteSubKeyTree(string subKey)
    {
        try
        {
            Registry.CurrentUser.DeleteSubKeyTree(subKey, throwOnMissingSubKey: false);
        }
        catch
        {
            // Best-effort removal
        }
    }
}
