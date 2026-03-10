# AtomicCipher

A post-quantum hybrid file encryption tool for Windows, built with WPF and .NET 10.

AtomicCipher combines **ML-KEM-768** (NIST-standardized post-quantum key encapsulation) with **AES-256-GCM** (authenticated symmetric encryption) to protect files and folders against both classical and quantum computing threats.

## Features

- **Post-quantum security** — ML-KEM-768 key encapsulation resistant to quantum attacks
- **Authenticated encryption** — AES-256-GCM per chunk + HMAC-SHA256 file integrity
- **File and folder encryption** — Encrypt individual files or entire directories
- **ZIP compression** — All content is compressed before encryption for smaller output
- **Encrypted metadata** — Original filenames are encrypted, not visible in `.acf` files
- **Streaming encryption** — 64 KiB chunked processing for memory-efficient large file handling
- **Windows Explorer integration** — Right-click context menu for encrypt/decrypt
- **Key persistence** — Key file paths remembered between sessions
- **Secure cleanup** — Temporary files overwritten with zeros before deletion

## Requirements

- Windows 10/11
- [.NET 10 SDK](https://dotnet.microsoft.com/download)

## Build & Run

```bash
dotnet restore
dotnet build
dotnet run
```

## Usage

### Generate Keys

1. Open AtomicCipher
2. Click **Generate New Key Pair**
3. Choose a save location — creates `name.acpub` (public) and `name.acpriv` (private)

### Encrypt a File or Folder

1. Load the **recipient's public key** (`.acpub`)
2. Select the file or folder to encrypt
3. Click **Encrypt** — produces a `.acf` file

### Decrypt

1. Load **your private key** (`.acpriv`)
2. Select the `.acf` file
3. Click **Decrypt** — restores the original file or folder

### Command Line

```bash
AtomicCipher.exe --encrypt "C:\path\to\file.txt"
AtomicCipher.exe --decrypt "C:\path\to\file.txt.acf"
```

### Windows Explorer Context Menu

Click **Install Context Menu** in Settings to add right-click options:
- **Encrypt with AtomicCipher** — appears on all files and folders
- **Decrypt with AtomicCipher** — appears on `.acf` files (also opens on double-click)

No admin privileges required (uses HKCU registry).

## How It Works

```
Sender                                    Recipient
──────                                    ─────────
                                          Generate key pair
                                          Share public key (.acpub)
                    ◄── .acpub ───
Encrypt file with
recipient's public key
                    ─── .acf ───►
                                          Decrypt with private key (.acpriv)
                                          Original file restored
```

### Encryption Pipeline

1. Source file/folder is ZIP-compressed
2. ML-KEM-768 encapsulates a fresh 32-byte symmetric key using the recipient's public key
3. Original filename is encrypted with AES-256-GCM
4. Compressed data is streamed through AES-256-GCM in 64 KiB chunks (each with a unique derived nonce)
5. HMAC-SHA256 is appended over the entire file for tamper detection

### Security Properties

| Property | Mechanism |
|----------|-----------|
| Post-quantum key exchange | ML-KEM-768 (NIST FIPS 203) |
| Symmetric encryption | AES-256-GCM (authenticated) |
| Per-file key isolation | Fresh KEM encapsulation per file |
| Chunk ordering protection | Nonce includes chunk index |
| Tamper detection | File-level HMAC-SHA256, verified before decryption |
| Metadata protection | Filename encrypted in header |
| Memory hygiene | Shared secrets zeroed after use |
| Temp file security | Overwritten with zeros, then deleted |

## File Formats

### Key Files

PEM-like text format:

- `.acpub` — Public key
- `.acpriv` — Private key (keep secret!)

```
-----BEGIN ATOMICCIPHER PUBLIC KEY-----
<base64 data>
-----END ATOMICCIPHER PUBLIC KEY-----
```

### Encrypted Files (`.acf`)

Binary format with magic bytes `ACF\0`, containing:
- File header (version, algorithms, encrypted filename, encapsulated key, nonce)
- Encrypted data chunks (ciphertext + GCM auth tags)
- HMAC-SHA256 integrity signature

## Project Structure

```
AtomicCipher/
├── Crypto/          ML-KEM-768 key management, AES-256-GCM chunked encryption,
│                    hybrid encrypt/decrypt facades
├── FileFormat/      Binary .acf format: header, reader, writer
├── Services/        ZIP archiving, secure temp files, settings, context menu
├── ViewModels/      MVVM: MainViewModel, RelayCommand
├── Exceptions/      AtomicCipherException, IntegrityException, KeyException
├── MainWindow.xaml  WPF UI (Catppuccin dark theme)
└── App.xaml         Application entry point with CLI argument handling
```

## License

All rights reserved.
