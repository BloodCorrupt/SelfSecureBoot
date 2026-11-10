using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace SelfSecureBoot.Core;

public sealed class CertificateInfo
{
    public string Subject { get; init; } = "";
    public DateTime? NotAfter { get; init; }
}

public sealed class KeyStore
{
    public string DirectoryPath { get; }
    public string KeyPath => Path.Combine(DirectoryPath, "db.key");
    public string CertPemPath => Path.Combine(DirectoryPath, "db.crt");
    public string CertDerPath => Path.Combine(DirectoryPath, "db.cer");
    public string EslPath => Path.Combine(DirectoryPath, "db.esl");
    public string BackupsDir => Path.Combine(DirectoryPath, "Backups");

    public const string MarkerName = "partition-uuid.txt";

    public KeyStore(string? customDirectory = null)
    {
        DirectoryPath = customDirectory ?? AppPaths.DataDir;
        Directory.CreateDirectory(DirectoryPath);
        Directory.CreateDirectory(BackupsDir);
    }

    public bool Exists => File.Exists(KeyPath) && File.Exists(CertPemPath);

    public SigningIdentity Identity()
    {
        return SigningIdentity.Load(KeyPath, CertPemPath);
    }

    public byte[]? CertificateDER
    {
        get
        {
            if (!File.Exists(CertPemPath)) return null;
            try
            {
                byte[] raw = File.ReadAllBytes(CertPemPath);
                return SigningIdentity.ExtractCertificateDer(raw);
            }
            catch
            {
                return null;
            }
        }
    }

    public CertificateInfo? GetCertificateInfo()
    {
        byte[]? der = CertificateDER;
        if (der == null) return null;

        string subject = Inspector.SubjectCommonName(der);
        if (string.IsNullOrWhiteSpace(subject)) subject = "certificate";

        return new CertificateInfo
        {
            Subject = subject,
            NotAfter = Inspector.NotAfter(der)
        };
    }

    /// <summary>
    /// Generates a new RSA private key and self-signed code signing certificate using pure .NET cryptography.
    /// </summary>
    public void Generate(string commonName, int days, int keySize = 2048)
    {
        string cn = commonName.Replace("\r", "").Replace("\n", " ").Replace("/", "-").Trim();
        if (string.IsNullOrEmpty(cn)) cn = "OpenCore Secure Boot Signing";

        using var rsa = RSA.Create(keySize);
        var req = new CertificateRequest($"CN={cn}", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

        req.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
        req.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));

        // Code signing OID: 1.3.6.1.5.5.7.3.3
        var eku = new OidCollection { new Oid("1.3.6.1.5.5.7.3.3") };
        req.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(eku, false));

        req.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(req.PublicKey, false));

        using var cert = req.CreateSelfSigned(
            DateTimeOffset.UtcNow.AddMinutes(-5),
            DateTimeOffset.UtcNow.AddDays(days)
        );

        // Export PKCS#8 PEM private key
        string keyPem = PemHelper.ToPem(rsa.ExportPkcs8PrivateKey(), "PRIVATE KEY");
        File.WriteAllText(KeyPath, keyPem, Encoding.UTF8);

        // Export PEM certificate
        string certPem = PemHelper.ToPem(cert.RawData, "CERTIFICATE");
        File.WriteAllText(CertPemPath, certPem, Encoding.UTF8);

        WriteDerivedFiles();

        // Verify it can be loaded back
        using var loaded = Identity();
    }

    public void ImportKey(string sourceKeyFile, string sourceCertFile)
    {
        // First validate by loading
        using (var id = SigningIdentity.Load(sourceKeyFile, sourceCertFile))
        {
            File.Copy(sourceKeyFile, KeyPath, overwrite: true);

            string certPem = PemHelper.ToPem(id.CertificateDER, "CERTIFICATE");
            File.WriteAllText(CertPemPath, certPem, Encoding.UTF8);
        }

        WriteDerivedFiles();
    }

    public void WriteDerivedFiles()
    {
        byte[]? der = CertificateDER;
        if (der == null) throw new InvalidOperationException("Certificate DER could not be extracted.");

        File.WriteAllBytes(CertDerPath, der);
        byte[] esl = Authenticode.MakeESL(der);
        File.WriteAllBytes(EslPath, esl);
    }

    /// <summary>
    /// Copies db.cer and db.esl into target directory (e.g. FAT32 USB stick for BIOS).
    /// </summary>
    public List<string> ExportCertificate(string destinationFolder)
    {
        if (!File.Exists(CertDerPath) || !File.Exists(EslPath))
        {
            WriteDerivedFiles();
        }

        Directory.CreateDirectory(destinationFolder);
        var exported = new List<string>();

        foreach (string file in new[] { CertDerPath, EslPath })
        {
            string fileName = Path.GetFileName(file);
            string dest = Path.Combine(destinationFolder, fileName);
            File.Copy(file, dest, overwrite: true);
            exported.Add(dest);
        }

        return exported;
    }

    public List<string> GetBackupFolders(string partitionId, string? partitionUuid)
    {
        if (!Directory.Exists(BackupsDir)) return [];

        var list = new List<string>();
        foreach (var dir in Directory.GetDirectories(BackupsDir).OrderBy(d => d))
        {
            string marker = Path.Combine(dir, MarkerName);
            if (!string.IsNullOrWhiteSpace(partitionUuid) && File.Exists(marker))
            {
                try
                {
                    string uuid = File.ReadAllText(marker, Encoding.UTF8).Trim();
                    if (string.Equals(uuid, partitionUuid, StringComparison.OrdinalIgnoreCase))
                    {
                        list.Add(dir);
                        continue;
                    }
                }
                catch { }
            }

            string name = Path.GetFileName(dir);
            if (name.Contains($" {partitionId} ", StringComparison.OrdinalIgnoreCase) ||
                name.EndsWith($" {partitionId}", StringComparison.OrdinalIgnoreCase))
            {
                list.Add(dir);
            }
        }

        return list;
    }

    public string GetOrCreateBackupFolder(string partitionId, string? partitionUuid, string volumeName)
    {
        string date = DateTime.Now.ToString("yyyy-MM-dd");
        // Strip all characters that are invalid in Windows directory names from both id and volume
        char[] invalidChars = Path.GetInvalidFileNameChars();
        string safeId = string.Concat(partitionId.Split(invalidChars)).Replace(" ", "_").Trim('_');
        string safeVol = string.Concat(volumeName.Split(invalidChars)).Replace(" ", "_").Trim('_');
        if (string.IsNullOrWhiteSpace(safeId)) safeId = "EFI";
        if (string.IsNullOrWhiteSpace(safeVol)) safeVol = "Volume";
        string name = $"{date}_{safeId}_{safeVol}".Trim('_');
        string dir = Path.Combine(BackupsDir, name);
        Directory.CreateDirectory(dir);

        if (!string.IsNullOrWhiteSpace(partitionUuid))
        {
            string marker = Path.Combine(dir, MarkerName);
            if (!File.Exists(marker))
            {
                File.WriteAllText(marker, partitionUuid.Trim(), Encoding.UTF8);
            }
        }

        return dir;
    }
}

