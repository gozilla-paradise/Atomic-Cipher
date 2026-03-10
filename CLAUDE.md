# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build Commands

```bash
dotnet restore    # Restore NuGet packages
dotnet build      # Build the project
dotnet run        # Run the application
```

Target framework is `net10.0-windows` (WPF). No test project exists.

## Architecture

**Hybrid post-quantum file encryption tool** with two modes: (1) ML-KEM-768 (via BouncyCastle 2.6.x) for asymmetric key encapsulation, or (2) **passphrase-only mode** using Argon2id key derivation. Both produce a 32-byte shared secret → AES-256-GCM for symmetric encryption. All files (single files and folders) are ZIP-compressed before encryption.

### Layer Overview

- **Crypto/** — Core cryptographic operations. `KyberKeyManager` handles ML-KEM-768 key gen/encapsulate/decapsulate and PEM key I/O. `ChunkedAesGcm` does streaming AES-256-GCM in 64 KiB chunks with per-chunk nonce derivation (base nonce XOR chunk index). `HybridEncryptor`/`HybridDecryptor` are the public API facades for KEM-based encryption. `PassphraseKeyDeriver` handles Argon2id key derivation with configurable params (salt, memory, iterations, parallelism). `PassphraseEncryptor` is the facade for passphrase-based encryption. `HybridDecryptor` also handles passphrase-mode decryption via an overload accepting `string passphrase`.
- **FileFormat/** — Binary `.acf` file format (version 2). `AtomicFileHeader` manages the header (magic `ACF\0`, version, `KeyDerivationMode` byte, encrypted filename, encapsulated key or KDF params blob, nonce, chunk metadata). `AtomicFileWriter`/`AtomicFileReader` handle streaming I/O with HMAC-SHA256 integrity at EOF.
- **Services/** — `FolderArchiver` (ZIP compression for both files and folders), `SecureTempFile` (IDisposable temp file that zero-overwrites on dispose), `SettingsManager` (persists key paths to `%LOCALAPPDATA%\AtomicCipher\settings.json`), `ContextMenuInstaller` (Windows Explorer context menu via HKCU registry).
- **ViewModels/** — MVVM pattern. `MainViewModel` drives all UI operations. `RelayCommand` implements ICommand.
- **Exceptions/** — `AtomicCipherException` (base), `IntegrityException` (HMAC/auth tag failure), `KeyException` (key format/load errors).

### Encryption Flow (KEM mode)

1. ZIP-compress source (file or folder) → secure temp file
2. `KyberKeyManager.Encapsulate(publicKey)` → encapsulated key + 32-byte shared secret
3. Encrypt filename with AES-GCM using shared secret (stored in header)
4. Write ACF header (mode=KEM), then stream 64 KiB chunks through `ChunkedAesGcm`
5. Append HMAC-SHA256 over all preceding bytes
6. Zero shared secret in `finally` block

### Encryption Flow (Passphrase mode)

1. ZIP-compress source → secure temp file
2. Generate 32-byte random salt → derive 32-byte key via Argon2id (64 MiB, 3 iterations, 4 parallelism)
3. Serialize KDF params as 44-byte blob (salt + memory + iterations + parallelism), store as `EncapsulatedKey` in header
4. Write ACF header (mode=Passphrase), then same AES-256-GCM chunk pipeline
5. Append HMAC-SHA256, zero derived key

### Decryption Flow

1. Read header → check `KeyDerivationMode`
2. **KEM mode**: decapsulate shared secret from encapsulated key using private key
3. **Passphrase mode**: deserialize KDF params from `EncapsulatedKey`, derive key from passphrase
4. **Verify file HMAC before any decryption** (reject tampered files / wrong passphrase early)
5. Decrypt original filename from header
6. Decrypt chunks, verify sizes match
7. Extract from ZIP (single file or folder based on `ContentType` flag)
8. Secure-delete temp files, zero shared secret

### ACF File Format v2

Version 2 adds a `KeyDerivationMode` byte after `SymmetricAlgorithm`. In passphrase mode, the `EncapsulatedKey` field stores a 44-byte KDF params blob: `[salt(32)] [memory_KiB(u32)] [iterations(u32)] [parallelism(u32)]`. Version 2 readers accept v1 files (default to KEM mode). V1 readers reject v2 files.

### CLI Integration

`App.xaml.cs` handles `--encrypt <path>`, `--encrypt-passphrase <path>`, and `--decrypt <path>` arguments (used by Explorer context menu). `--encrypt-passphrase` opens UI in passphrase mode. `--decrypt` auto-detects mode from file header. No `StartupUri` in `App.xaml`; window is created in `OnStartup`.

## BouncyCastle API Notes

BouncyCastle 2.6.x uses `MLKem*` types (not `Kyber*`):
- Namespaces: `Org.BouncyCastle.Crypto.{Parameters,Generators,Kems}`
- Key reconstruction: `MLKemPublicKeyParameters.FromEncoding()` / `MLKemPrivateKeyParameters.FromEncoding()` (static factory methods, no public constructors)
- Encapsulation: `MLKemEncapsulator(MLKemParameters.ml_kem_768)` → `.Init(pubKey)` → `.Encapsulate(encBuf, 0, len, secBuf, 0, len)`
- Decapsulation: `MLKemDecapsulator(MLKemParameters.ml_kem_768)` → `.Init(privKey)` → `.Decapsulate(encBuf, 0, len, secBuf, 0, len)`

## Post-Implementation Maintenance

After finishing any implementation that changes the structure or public API of this codebase, update this file with:
- New or renamed files/classes and their purpose
- Changes to encryption/decryption flows
- New dependencies or build configuration changes
- New conventions or patterns introduced
- Changes to the `.acf` binary format (bump version if breaking)
- New CLI arguments or UI sections

## Key Conventions

- `ImplicitUsings` is enabled but does **not** include `System.IO` — add it explicitly in files using IO types
- `AllowUnsafeBlocks` is enabled for P/Invoke in `ContextMenuInstaller`
- Key files use `.acpub` / `.acpriv` extensions with PEM-like format (`-----BEGIN ATOMICCIPHER PUBLIC KEY-----`)
- Encrypted files use `.acf` extension with binary format (magic: `ACF\0`, version 2; backward-compatible with v1)
- Security-sensitive code must zero secrets with `CryptographicOperations.ZeroMemory()` in `finally` blocks
- `SecureTempFile` must be used for any intermediate plaintext written to disk
