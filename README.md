# EFI Signer (SelfSecureBoot)

A cross-platform UEFI Secure Boot manager and Authenticode PE signer for OpenCore, built with **C# (.NET 10)** and **Avalonia UI** for **Windows** and **Linux**.

Ported from macOS [efisigner](https://github.com/razvanccr/efisigner) and styled using the dark Fluent design.

---

## 🚀 Key Features

* **Authenticode PE Signer (Pure C#)**:
  * Strips old signatures, aligns to 8-byte boundaries, calculates PE Authenticode SHA-256 hashes according to UEFI specification.
  * Generates PKCS#7 SignedData structures containing `SpcIndirectDataContent` and signs with custom RSA keys.
  * Appends standard `WIN_CERTIFICATE` table and recalculates PE optional header checksums.
  * In-memory self-check verification before saving modified binaries to disk.
* **Inline EFI File & Partition Browser**:
  * On Windows & Linux, automatically detects physical disks and EFI system partitions (`{c12a7328-f81f-11d2-ba4b-00a0c93ec93b}` and system FAT32 volumes).
  * **Inline Mounting**: 1-click mounting (e.g. to drive `Z:\`) and unmounting with automatic Administrator / sudo privilege detection.
  * **Inbuilt File Browser**: Allows users to select any folder or partition path inline without requiring manual disk mounting.
  * Quick subfolder jump buttons (`EFI`, `OC`, `BOOT`, `Microsoft`).
* **OpenCore `config.plist` Analysis & Automatic Fixes**:
  * Inspects `Misc > Security > SecureBootModel`: Warns if set to `Disabled` and offers 1-click fix to `Default`.
  * Inspects `UEFI > Quirks > DisableSecurityPolicy`: Warns if set to `true` and offers 1-click fix to `false`.
  * Inspects `Misc > Tools`: Detects enabled `OpenShell.efi` / `Shell.efi` and offers 1-click fix to disable them.
  * Preserves timestamped backups before applying fixes.
* **Full Revert & Restore**:
  * 1-click revert of signed files back to their original un-signed or OEM versions from historical backups.
  * 1-click restoration of original `config.plist`.
* **Integrated Key Management**:
  * Pure .NET X.509 RSA-2048/3072/4096 key and certificate generation (no OpenSSL installation required).
  * Import existing keys (`db.key` / `db.crt`).
  * Generates UEFI-compliant EFI Signature Lists (`db.esl`) and DER certificates (`db.cer`).
  * 1-click export to FAT32 USB sticks for motherboard BIOS enrollment.
* **Firmware Detection**:
  * Reads UEFI Secure Boot enforcement status, Setup Mode, and OpenCore version across Windows and Linux.
* **Built-in Documentation**:
  * Step-by-step BIOS enrollment walkthrough for ASUS, ASRock, Gigabyte, MSI, Dell, Lenovo, and HP motherboards with official vendor links.

---

## 🧪 Automated Self-Test Suite

The application includes an automated verification test suite verifying all cryptographic operations, PE parsing, in-memory signing, signature validation on genuine Windows bootloaders, and OpenCore XML fixes:

```bash
dotnet run -- --test
```

---

## 📦 Building & Publishing

### Prerequisites
* [.NET 10 SDK](https://dotnet.microsoft.com/)

### Run Development Build
```bash
run.bat
# or
dotnet run
```

### Build Single-File Standalone Packages
```bash
build.bat
```
Produces:
* `distribute\win-x64\SelfSecureBoot.exe` (Windows portable single-file binary)
* `distribute\linux-x64\SelfSecureBoot` (Linux x64 self-contained executable)

---

## 📋 BIOS Enrollment Walkthrough

1. Open **EFI Signer**, click **Generate New Key...** (or import your existing `db.key` & `db.crt`).
2. Select your boot disk's EFI partition in the left sidebar (or click **Browse...** to point directly to an EFI folder). If not mounted, click **Mount (Z:)**.
3. If OpenCore warnings appear, click the inline **Fix** buttons.
4. Click **Sign needed** to sign all bootloaders and drivers.
5. Click **Export for BIOS** to copy `db.cer` and `db.esl` to a FAT32 USB flash drive.
6. Reboot into BIOS: Under **Secure Boot**, switch to **Custom** mode, select **Key Management** → **db** → **Append** / **Add from file**, and choose `db.cer`. Keep Microsoft's keys intact.
7. Set Secure Boot to **Enabled**, save, and reboot.

