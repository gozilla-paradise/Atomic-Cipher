<img width="959" height="930" alt="image" src="https://github.com/user-attachments/assets/f13ac027-1eeb-4963-8b25-b6725e0e1248" />


# AtomicCipher

A post-quantum hybrid file encryption tool for Windows, built with WPF and .NET 10.

AtomicCipher combines **ML-KEM-768** (NIST-standardized post-quantum key encapsulation) with **AES-256-GCM** (authenticated symmetric encryption) to protect files and folders against both classical and quantum computing threats. It also supports a **passphrase-only mode** using Argon2id key derivation for quick sharing without exchanging key files.

## Features

- **Post-quantum security** — ML-KEM-768 key encapsulation resistant to quantum attacks
- **Passphrase-only mode** — Argon2id key derivation (64 MiB, 3 iterations) for encrypting without key files
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

### Encrypt a File or Folder (Key Mode)

1. Select **KEY** mode in the encrypt panel
2. Load the **recipient's public key** (`.acpub`)
3. Select the file or folder to encrypt
4. Click **Encrypt** — produces a `.acf` file

### Encrypt a File or Folder (Passphrase Mode)

1. Select **PASSPHRASE** mode in the encrypt panel
2. Enter a passphrase and confirm it
3. Select the file or folder to encrypt
4. Click **Encrypt** — produces a `.acf` file (no key files needed)

### Decrypt

1. Load **your private key** (`.acpriv`) for key-encrypted files
2. For passphrase-encrypted files, enter the passphrase in the decrypt panel
3. Select the `.acf` file(s) — the mode is auto-detected from the file header
4. Click **Decrypt** — restores the original file or folder

### Command Line

```bash
AtomicCipher.exe --encrypt "C:\path\to\file.txt"
AtomicCipher.exe --encrypt-passphrase "C:\path\to\file.txt"
AtomicCipher.exe --decrypt "C:\path\to\file.txt.acf"
```

### Windows Explorer Context Menu

Click **Install Context Menu** in Settings to add right-click options:
- **Encrypt with AtomicCipher** — appears on all files and folders
- **Decrypt with AtomicCipher** — appears on `.acf` files (also opens on double-click)

No admin privileges required (uses HKCU registry).

## How It Works

```
Key Mode:
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

Passphrase Mode:
  Sender                                    Recipient
  ──────                                    ─────────
  Encrypt with passphrase
                      ─── .acf ───►
                                            Decrypt with same passphrase
                                            Original file restored
```

### Encryption Pipeline (Key Mode)

1. Source file/folder is ZIP-compressed
2. ML-KEM-768 encapsulates a fresh 32-byte symmetric key using the recipient's public key
3. Original filename is encrypted with AES-256-GCM
4. Compressed data is streamed through AES-256-GCM in 64 KiB chunks (each with a unique derived nonce)
5. HMAC-SHA256 is appended over the entire file for tamper detection

### Encryption Pipeline (Passphrase Mode)

1. Source file/folder is ZIP-compressed
2. A 32-byte random salt is generated
3. A 32-byte symmetric key is derived from the passphrase via **Argon2id** (64 MiB memory, 3 iterations, 4 parallelism)
4. KDF parameters (salt + config) are stored in the file header as a 44-byte blob
5. Same AES-256-GCM chunk encryption and HMAC-SHA256 pipeline as key mode

### Security Properties

| Property | Mechanism |
|----------|-----------|
| Post-quantum key exchange | ML-KEM-768 (NIST FIPS 203) |
| Passphrase key derivation | Argon2id (memory-hard, GPU-resistant) |
| Symmetric encryption | AES-256-GCM (authenticated) |
| Per-file key isolation | Fresh KEM encapsulation or fresh salt per file |
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

Binary format v2 with magic bytes `ACF\0`, containing:
- File header (version, algorithms, key derivation mode, encrypted filename, encapsulated key or KDF params, nonce)
- Encrypted data chunks (ciphertext + GCM auth tags)
- HMAC-SHA256 integrity signature

Version 2 is backward-compatible with v1 files (treated as KEM mode).

## Project Structure

```
AtomicCipher/
├── Crypto/          ML-KEM-768 key management, Argon2id passphrase derivation,
│                    AES-256-GCM chunked encryption, hybrid + passphrase facades
├── FileFormat/      Binary .acf format: header, reader, writer
├── Services/        ZIP archiving, secure temp files, settings, context menu
├── ViewModels/      MVVM: MainViewModel, RelayCommand
├── Exceptions/      AtomicCipherException, IntegrityException, KeyException
├── MainWindow.xaml  WPF UI (Catppuccin dark theme)
└── App.xaml         Application entry point with CLI argument handling
```

## License

All rights reserved.
