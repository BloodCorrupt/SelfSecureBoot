using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace SelfSecureBoot.Core;

public enum FileRole
{
    OpenCore,
    Bootstrap,
    Windows,
    Linux,
    AppleUpdater,
    AppleBoot,
    Other
}

public static class FileRoleExtensions
{
    public static string DisplayName(this FileRole role) => role switch
    {
        FileRole.OpenCore => "OpenCore",
        FileRole.Bootstrap => "Fallback loader (BOOT)",
        FileRole.Windows => "Windows Boot Manager",
        FileRole.Linux => "Linux / shim",
        FileRole.AppleUpdater => "Apple firmware updater",
        FileRole.AppleBoot => "macOS boot file",
        _ => "Other"
    };

    public static FileRole Classify(string relativePath)
    {
        string p = relativePath.Replace('\\', '/').ToLowerInvariant();
        if (p.StartsWith("efi/oc/")) return FileRole.OpenCore;
        if (p.StartsWith("efi/boot/")) return FileRole.Bootstrap;
        if (p.StartsWith("efi/microsoft/")) return FileRole.Windows;
        if (p.StartsWith("efi/apple/")) return FileRole.AppleUpdater;
        if (p.EndsWith("coreservices/boot.efi") || p.EndsWith("/apfs.efi") ||
            p.StartsWith("system/library/") || p.StartsWith("usr/standalone/"))
            return FileRole.AppleBoot;

        if (p.Contains("shim") || p.Contains("grub") ||
            p.StartsWith("efi/ubuntu/") || p.StartsWith("efi/fedora/") ||
            p.StartsWith("efi/debian/") || p.StartsWith("efi/systemd/"))
            return FileRole.Linux;

        return FileRole.Other;
    }
}

public enum Verdict
{
    NeedsSignature,
    SignedByUs,
    SignedOther,
    SignedInvalid,
    DisabledInConfig,
    NotLoaded,
    AppleSigned,
    NotPE
}

public static class VerdictExtensions
{
    public static string DisplayName(this Verdict verdict) => verdict switch
    {
        Verdict.NeedsSignature => "Needs signing",
        Verdict.SignedByUs => "Signed with your key",
        Verdict.SignedOther => "Signed (other key)",
        Verdict.SignedInvalid => "Signature broken",
        Verdict.DisabledInConfig => "Not loaded (disabled in config)",
        Verdict.NotLoaded => "Not loaded by firmware",
        Verdict.AppleSigned => "Apple-signed, handled by OpenCore",
        Verdict.NotPE => "Not a PE image",
        _ => "Unknown"
    };

    public static bool BlocksSecureBoot(this Verdict verdict) =>
        verdict is Verdict.NeedsSignature or Verdict.SignedInvalid;
}

public sealed class EFIFileEntry
{
    public string Id => FullPath;
    public string FullPath { get; init; } = "";
    public string RelativePath { get; init; } = "";
    public long Size { get; init; }
    public FileStatus Status { get; init; } = FileStatus.Unsigned();
    public FileRole Role { get; init; }
    public bool? LoadedByConfig { get; init; }
    public Verdict Verdict { get; init; }

    public string SignerDescription
    {
        get
        {
            return Status switch
            {
                FileStatus.NotPEStatus notPe => notPe.Reason,
                FileStatus.UnsignedStatus => "—",
                FileStatus.AppleFormatStatus => "Apple EFI signature (not PKCS#7)",
                FileStatus.SignedStatus signed => FormatSignedInfo(signed.Info),
                _ => "—"
            };
        }
    }

    private static string FormatSignedInfo(SignatureInfo info)
    {
        string s = info.SignerName;
        if (info.NotAfter.HasValue)
        {
            s += $" (until {info.NotAfter.Value:yyyy-MM-dd})";
        }
        if (info.Problems.Count > 0)
        {
            s += " · " + string.Join("; ", info.Problems);
        }
        return s;
    }
}

public static class Scanner
{
    public static (List<EFIFileEntry> Entries, OpenCoreConfig? Config) Scan(string rootDirectory, byte[]? trustedCertificateDer)
    {
        if (!Directory.Exists(rootDirectory))
            return (new List<EFIFileEntry>(), null);

        var config = OpenCoreConfig.Load(rootDirectory);
        var entries = new List<EFIFileEntry>();

        var allFiles = Directory.EnumerateFiles(rootDirectory, "*.efi", SearchOption.AllDirectories);
        string normalizedRoot = Path.GetFullPath(rootDirectory).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);

        foreach (string file in allFiles)
        {
            string fullPath = Path.GetFullPath(file);
            string rel = fullPath.StartsWith(normalizedRoot, StringComparison.OrdinalIgnoreCase)
                ? fullPath[(normalizedRoot.Length + 1)..].Replace('\\', '/')
                : Path.GetFileName(file);

            if (Path.GetFileName(file).StartsWith("._")) continue; // Skip macOS metadata files

            long size = 0;
            try { size = new FileInfo(fullPath).Length; } catch { }

            var status = Inspector.Inspect(fullPath);
            var role = FileRoleExtensions.Classify(rel);
            var loaded = config?.IsLoaded(rel);
            var verdict = DetermineVerdict(status, role, loaded, trustedCertificateDer);

            entries.Add(new EFIFileEntry
            {
                FullPath = fullPath,
                RelativePath = rel,
                Size = size,
                Status = status,
                Role = role,
                LoadedByConfig = loaded,
                Verdict = verdict
            });
        }

        entries.Sort((a, b) => string.Compare(a.RelativePath, b.RelativePath, StringComparison.OrdinalIgnoreCase));
        return (entries, config);
    }

    public static Verdict DetermineVerdict(FileStatus status, FileRole role, bool? loaded, byte[]? trusted)
    {
        if (status is FileStatus.NotPEStatus) return Verdict.NotPE;
        if (role == FileRole.AppleUpdater) return Verdict.NotLoaded;
        if (role == FileRole.AppleBoot || status is FileStatus.AppleFormatStatus) return Verdict.AppleSigned;
        if (loaded == false) return Verdict.DisabledInConfig;

        if (status is FileStatus.UnsignedStatus)
        {
            return Verdict.NeedsSignature;
        }

        if (status is FileStatus.SignedStatus signed)
        {
            if (!signed.Info.IsValid) return Verdict.SignedInvalid;

            if (trusted != null && signed.Info.SignerCertificateDER != null &&
                signed.Info.SignerCertificateDER.AsSpan().SequenceEqual(trusted))
            {
                return Verdict.SignedByUs;
            }

            return Verdict.SignedOther;
        }

        return Verdict.NotPE;
    }
}

public sealed record SignOutcome(EFIFileEntry Entry, byte[]? Hash, string? Error);

public static class SignerService
{
    /// <summary>
    /// Signs the file in place, keeping a copy of the original under backupRoot/relativePath (first time only).
    /// </summary>
    public static SignOutcome Sign(EFIFileEntry entry, SigningIdentity identity, string? backupRoot)
    {
        try
        {
            byte[] original = File.ReadAllBytes(entry.FullPath);

            if (!string.IsNullOrEmpty(backupRoot))
            {
                string dest = Path.Combine(backupRoot, entry.RelativePath.Replace('/', Path.DirectorySeparatorChar));
                string? parentDir = Path.GetDirectoryName(dest);
                if (!string.IsNullOrEmpty(parentDir)) Directory.CreateDirectory(parentDir);

                if (!File.Exists(dest))
                {
                    File.WriteAllBytes(dest, original);
                }
            }

            var (signed, hash) = Authenticode.Sign(original, identity);

            // Self-check newly signed binary in memory before touching disk
            var inspectResult = Inspector.Inspect(signed);
            if (inspectResult is not FileStatus.SignedStatus s ||
                !s.Info.IsValid ||
                s.Info.SignerCertificateDER == null ||
                !s.Info.SignerCertificateDER.AsSpan().SequenceEqual(identity.CertificateDER))
            {
                throw new InvalidOperationException("Self-check of the new signature failed; file left untouched on disk.");
            }

            File.WriteAllBytes(entry.FullPath, signed);
            return new SignOutcome(entry, hash, null);
        }
        catch (Exception ex)
        {
            return new SignOutcome(entry, null, ex.Message);
        }
    }
}

