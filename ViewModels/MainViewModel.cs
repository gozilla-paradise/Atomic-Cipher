using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Runtime.CompilerServices;
using System.Windows;
using System.Windows.Input;
using AtomicCipher.Crypto;
using AtomicCipher.FileFormat;
using AtomicCipher.Services;
using Microsoft.Win32;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;

namespace AtomicCipher.ViewModels;

public enum EncryptionMode
{
    KeyBased,
    Passphrase
}

public class MainViewModel : INotifyPropertyChanged
{
    private string _statusText = "Ready.";
    private string _publicKeyPath = string.Empty;
    private string _privateKeyPath = string.Empty;
    private double _progressValue;
    private bool _isBusy;
    private bool _contextMenuInstalled;
    private EncryptionMode _selectedEncryptMode = EncryptionMode.KeyBased;
    private string _encryptPassphrase = string.Empty;
    private string _encryptPassphraseConfirm = string.Empty;
    private string _decryptPassphrase = string.Empty;
    private CancellationTokenSource? _cts;

    public MainViewModel()
    {
        GenerateKeysCommand = new RelayCommand(async () => await GenerateKeysAsync(), () => !IsBusy);
        BrowsePublicKeyCommand = new RelayCommand(BrowsePublicKey);
        BrowsePrivateKeyCommand = new RelayCommand(BrowsePrivateKey);
        BrowseEncryptSourceCommand = new RelayCommand(BrowseEncryptSource);
        BrowseDecryptSourceCommand = new RelayCommand(BrowseDecryptSource);
        EncryptCommand = new RelayCommand(async () => await EncryptAsync(), () => !IsBusy);
        DecryptCommand = new RelayCommand(async () => await DecryptAsync(), () => !IsBusy);
        ToggleContextMenuCommand = new RelayCommand(ToggleContextMenu, () => !IsBusy);
        CancelCommand = new RelayCommand(Cancel, () => IsBusy);
        RemoveEncryptPathCommand = new RelayCommand<string>(RemoveEncryptPath);
        RemoveDecryptPathCommand = new RelayCommand<string>(RemoveDecryptPath);
        SelectKeyModeCommand = new RelayCommand(() => SelectedEncryptMode = EncryptionMode.KeyBased);
        SelectPassphraseModeCommand = new RelayCommand(() => SelectedEncryptMode = EncryptionMode.Passphrase);

        _contextMenuInstalled = ContextMenuInstaller.IsInstalled();

        var settings = SettingsManager.Load();
        _publicKeyPath = settings.PublicKeyPath;
        _privateKeyPath = settings.PrivateKeyPath;
    }

    public event PropertyChangedEventHandler? PropertyChanged;

    public string StatusText
    {
        get => _statusText;
        set => SetField(ref _statusText, value);
    }

    public string PublicKeyPath
    {
        get => _publicKeyPath;
        set { if (SetField(ref _publicKeyPath, value)) SaveKeySettings(); }
    }

    public string PrivateKeyPath
    {
        get => _privateKeyPath;
        set { if (SetField(ref _privateKeyPath, value)) SaveKeySettings(); }
    }

    public EncryptionMode SelectedEncryptMode
    {
        get => _selectedEncryptMode;
        set
        {
            if (SetField(ref _selectedEncryptMode, value))
            {
                OnPropertyChanged(nameof(IsKeyEncryptMode));
                OnPropertyChanged(nameof(IsPassphraseEncryptMode));
            }
        }
    }

    public bool IsKeyEncryptMode => SelectedEncryptMode == EncryptionMode.KeyBased;
    public bool IsPassphraseEncryptMode => SelectedEncryptMode == EncryptionMode.Passphrase;

    public string EncryptPassphrase
    {
        get => _encryptPassphrase;
        set => SetField(ref _encryptPassphrase, value);
    }

    public string EncryptPassphraseConfirm
    {
        get => _encryptPassphraseConfirm;
        set => SetField(ref _encryptPassphraseConfirm, value);
    }

    public string DecryptPassphrase
    {
        get => _decryptPassphrase;
        set => SetField(ref _decryptPassphrase, value);
    }

    public ObservableCollection<string> EncryptSourcePaths { get; } = [];
    public ObservableCollection<string> DecryptSourcePaths { get; } = [];

    public double ProgressValue
    {
        get => _progressValue;
        set => SetField(ref _progressValue, value);
    }

    public bool IsBusy
    {
        get => _isBusy;
        set => SetField(ref _isBusy, value);
    }

    public bool ContextMenuInstalled
    {
        get => _contextMenuInstalled;
        set => SetField(ref _contextMenuInstalled, value);
    }

    public ICommand GenerateKeysCommand { get; }
    public ICommand BrowsePublicKeyCommand { get; }
    public ICommand BrowsePrivateKeyCommand { get; }
    public ICommand BrowseEncryptSourceCommand { get; }
    public ICommand BrowseDecryptSourceCommand { get; }
    public ICommand EncryptCommand { get; }
    public ICommand DecryptCommand { get; }
    public ICommand ToggleContextMenuCommand { get; }
    public ICommand CancelCommand { get; }
    public ICommand RemoveEncryptPathCommand { get; }
    public ICommand RemoveDecryptPathCommand { get; }
    public ICommand SelectKeyModeCommand { get; }
    public ICommand SelectPassphraseModeCommand { get; }

    public void SetEncryptPaths(params string[] paths)
    {
        EncryptSourcePaths.Clear();
        foreach (string path in paths)
            EncryptSourcePaths.Add(path);
    }

    public void SetDecryptPaths(params string[] paths)
    {
        DecryptSourcePaths.Clear();
        foreach (string path in paths)
            DecryptSourcePaths.Add(path);
    }

    private void RemoveEncryptPath(string? path)
    {
        if (path != null) EncryptSourcePaths.Remove(path);
    }

    private void RemoveDecryptPath(string? path)
    {
        if (path != null) DecryptSourcePaths.Remove(path);
    }

    private async Task GenerateKeysAsync()
    {
        var dialog = new SaveFileDialog
        {
            Title = "Save Key Pair — Choose base name",
            Filter = "AtomicCipher Public Key (*.acpub)|*.acpub",
            DefaultExt = ".acpub"
        };

        if (dialog.ShowDialog() != true) return;

        string basePath = dialog.FileName;
        string pubPath = Path.ChangeExtension(basePath, ".acpub");
        string privPath = Path.ChangeExtension(basePath, ".acpriv");

        IsBusy = true;
        StatusText = "Generating ML-KEM-768 key pair...";
        try
        {
            await Task.Run(async () =>
            {
                AsymmetricCipherKeyPair keyPair = KyberKeyManager.GenerateKeyPair();
                var pubKey = (MLKemPublicKeyParameters)keyPair.Public;
                var privKey = (MLKemPrivateKeyParameters)keyPair.Private;

                await KyberKeyManager.SavePublicKeyAsync(pubKey, pubPath);
                await KyberKeyManager.SavePrivateKeyAsync(privKey, privPath);
            });

            PublicKeyPath = pubPath;
            PrivateKeyPath = privPath;
            StatusText = $"Key pair generated: {Path.GetFileName(pubPath)} / {Path.GetFileName(privPath)}";
        }
        catch (Exception ex)
        {
            StatusText = $"Key generation failed: {ex.Message}";
        }
        finally
        {
            IsBusy = false;
        }
    }

    private void BrowsePublicKey()
    {
        var dialog = new OpenFileDialog
        {
            Title = "Select Public Key",
            Filter = "AtomicCipher Public Key (*.acpub)|*.acpub|All files (*.*)|*.*"
        };
        if (dialog.ShowDialog() == true)
            PublicKeyPath = dialog.FileName;
    }

    private void BrowsePrivateKey()
    {
        var dialog = new OpenFileDialog
        {
            Title = "Select Private Key",
            Filter = "AtomicCipher Private Key (*.acpriv)|*.acpriv|All files (*.*)|*.*"
        };
        if (dialog.ShowDialog() == true)
            PrivateKeyPath = dialog.FileName;
    }

    private void BrowseEncryptSource()
    {
        var dialog = new OpenFileDialog
        {
            Title = "Select Files to Encrypt",
            Filter = "All files (*.*)|*.*",
            Multiselect = true
        };
        if (dialog.ShowDialog() == true)
        {
            foreach (string file in dialog.FileNames)
            {
                if (!EncryptSourcePaths.Contains(file))
                    EncryptSourcePaths.Add(file);
            }
        }
    }

    private void BrowseDecryptSource()
    {
        var dialog = new OpenFileDialog
        {
            Title = "Select .acf Files to Decrypt",
            Filter = "AtomicCipher Files (*.acf)|*.acf|All files (*.*)|*.*",
            Multiselect = true
        };
        if (dialog.ShowDialog() == true)
        {
            foreach (string file in dialog.FileNames)
            {
                if (!DecryptSourcePaths.Contains(file))
                    DecryptSourcePaths.Add(file);
            }
        }
    }

    private async Task EncryptAsync()
    {
        if (EncryptSourcePaths.Count == 0)
        {
            StatusText = "Please select files or folders to encrypt.";
            return;
        }

        if (IsPassphraseEncryptMode)
        {
            if (string.IsNullOrEmpty(EncryptPassphrase))
            {
                StatusText = "Please enter a passphrase.";
                return;
            }
            if (EncryptPassphrase != EncryptPassphraseConfirm)
            {
                StatusText = "Passphrases do not match.";
                return;
            }
        }
        else
        {
            if (string.IsNullOrWhiteSpace(PublicKeyPath))
            {
                StatusText = "Please select a public key.";
                return;
            }
        }

        IsBusy = true;
        ProgressValue = 0;
        _cts = new CancellationTokenSource();

        int total = EncryptSourcePaths.Count;
        int completed = 0;
        int failed = 0;

        try
        {
            MLKemPublicKeyParameters? publicKey = null;
            if (IsKeyEncryptMode)
                publicKey = await KyberKeyManager.LoadPublicKeyAsync(PublicKeyPath);

            var paths = EncryptSourcePaths.ToList();

            foreach (string sourcePath in paths)
            {
                _cts.Token.ThrowIfCancellationRequested();

                bool isDirectory = Directory.Exists(sourcePath);
                bool isFile = File.Exists(sourcePath);

                if (!isDirectory && !isFile)
                {
                    failed++;
                    continue;
                }

                string fileName = Path.GetFileName(sourcePath);
                StatusText = $"Encrypting ({completed + 1}/{total}): {fileName}...";

                string outputPath = sourcePath + ".acf";
                long totalSize = isDirectory ? GetDirectorySize(sourcePath) : new FileInfo(sourcePath).Length;

                var progress = new Progress<long>(bytesProcessed =>
                {
                    double fileProgress = totalSize > 0 ? (double)bytesProcessed / totalSize : 0;
                    ProgressValue = ((completed + fileProgress) / total) * 100;
                });

                try
                {
                    if (IsPassphraseEncryptMode)
                    {
                        if (isDirectory)
                        {
                            await PassphraseEncryptor.EncryptFolderAsync(
                                sourcePath, outputPath, EncryptPassphrase, progress, _cts.Token);
                        }
                        else
                        {
                            await PassphraseEncryptor.EncryptFileAsync(
                                sourcePath, outputPath, EncryptPassphrase, progress, _cts.Token);
                        }
                    }
                    else
                    {
                        if (isDirectory)
                        {
                            await HybridEncryptor.EncryptFolderAsync(
                                sourcePath, outputPath, publicKey!, progress, _cts.Token);
                        }
                        else
                        {
                            await HybridEncryptor.EncryptFileAsync(
                                sourcePath, outputPath, publicKey!, progress, _cts.Token);
                        }
                    }
                    completed++;
                }
                catch (OperationCanceledException) { throw; }
                catch
                {
                    failed++;
                }
            }

            ProgressValue = 100;
            if (failed == 0)
                StatusText = $"Encrypted {completed} file(s) successfully.";
            else
                StatusText = $"Encrypted {completed} file(s), {failed} failed.";
        }
        catch (OperationCanceledException)
        {
            StatusText = "Encryption cancelled.";
        }
        catch (Exception ex)
        {
            StatusText = $"Encryption failed: {ex.Message}";
        }
        finally
        {
            IsBusy = false;
            _cts?.Dispose();
            _cts = null;
        }
    }

    private async Task DecryptAsync()
    {
        if (DecryptSourcePaths.Count == 0)
        {
            StatusText = "Please select .acf files to decrypt.";
            return;
        }

        IsBusy = true;
        ProgressValue = 0;
        _cts = new CancellationTokenSource();

        int total = DecryptSourcePaths.Count;
        int completed = 0;
        int failed = 0;

        try
        {
            MLKemPrivateKeyParameters? privateKey = null;
            var paths = DecryptSourcePaths.ToList();

            foreach (string sourcePath in paths)
            {
                _cts.Token.ThrowIfCancellationRequested();

                if (!File.Exists(sourcePath))
                {
                    failed++;
                    continue;
                }

                string fileName = Path.GetFileName(sourcePath);
                StatusText = $"Decrypting ({completed + 1}/{total}): {fileName}...";

                string outputDir = Path.GetDirectoryName(sourcePath) ?? Environment.CurrentDirectory;
                long totalSize = new FileInfo(sourcePath).Length;

                var progress = new Progress<long>(bytesProcessed =>
                {
                    double fileProgress = totalSize > 0 ? (double)bytesProcessed / totalSize : 0;
                    ProgressValue = ((completed + fileProgress) / total) * 100;
                });

                try
                {
                    var mode = HybridDecryptor.DetectMode(sourcePath);

                    if (mode == KeyDerivationMode.Passphrase)
                    {
                        if (string.IsNullOrEmpty(DecryptPassphrase))
                        {
                            StatusText = $"File '{fileName}' requires a passphrase. Please enter one.";
                            failed++;
                            continue;
                        }

                        await HybridDecryptor.DecryptFileAsync(
                            sourcePath, outputDir, DecryptPassphrase, progress, _cts.Token);
                    }
                    else
                    {
                        if (privateKey == null)
                        {
                            if (string.IsNullOrWhiteSpace(PrivateKeyPath))
                            {
                                StatusText = $"File '{fileName}' requires a private key. Please select one.";
                                failed++;
                                continue;
                            }
                            privateKey = await KyberKeyManager.LoadPrivateKeyAsync(PrivateKeyPath);
                        }

                        await HybridDecryptor.DecryptFileAsync(
                            sourcePath, outputDir, privateKey, progress, _cts.Token);
                    }
                    completed++;
                }
                catch (OperationCanceledException) { throw; }
                catch
                {
                    failed++;
                }
            }

            ProgressValue = 100;
            if (failed == 0)
                StatusText = $"Decrypted {completed} file(s) successfully.";
            else
                StatusText = $"Decrypted {completed} file(s), {failed} failed.";
        }
        catch (OperationCanceledException)
        {
            StatusText = "Decryption cancelled.";
        }
        catch (Exception ex)
        {
            StatusText = $"Decryption failed: {ex.Message}";
        }
        finally
        {
            IsBusy = false;
            _cts?.Dispose();
            _cts = null;
        }
    }

    private void ToggleContextMenu()
    {
        try
        {
            if (ContextMenuInstalled)
            {
                ContextMenuInstaller.Uninstall();
                ContextMenuInstalled = false;
                StatusText = "Context menu entries removed.";
            }
            else
            {
                string exePath = Process.GetCurrentProcess().MainModule?.FileName
                    ?? throw new InvalidOperationException("Could not determine executable path.");
                ContextMenuInstaller.Install(exePath);
                ContextMenuInstalled = true;
                StatusText = "Context menu entries installed.";
            }
        }
        catch (Exception ex)
        {
            StatusText = $"Context menu operation failed: {ex.Message}";
        }
    }

    private void Cancel()
    {
        _cts?.Cancel();
    }

    private void SaveKeySettings()
    {
        SettingsManager.Save(new AppSettings
        {
            PublicKeyPath = _publicKeyPath,
            PrivateKeyPath = _privateKeyPath
        });
    }

    private static long GetDirectorySize(string path)
    {
        return new DirectoryInfo(path)
            .EnumerateFiles("*", SearchOption.AllDirectories)
            .Sum(f => f.Length);
    }

    private bool SetField<T>(ref T field, T value, [CallerMemberName] string? propertyName = null)
    {
        if (EqualityComparer<T>.Default.Equals(field, value)) return false;
        field = value;
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
        return true;
    }

    private void OnPropertyChanged([CallerMemberName] string? propertyName = null)
    {
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
    }
}
