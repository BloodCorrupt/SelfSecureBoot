using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;

namespace SelfSecureBoot.Core;

public static class CliHandler
{
    public static bool IsCliCommand(string[] args)
    {
        if (args.Length == 0) return false;
        string first = args[0].ToLowerInvariant().TrimStart('-');
        return first is "hash" or "inspect" or "sign" or "esl" or "scan" or
                       "firmware" or "disks" or "strip" or "revert" or "fix-config" or
                       "help" or "h" or "?";
    }

    public static int Run(string[] rawArgs)
    {
        if (rawArgs.Length == 0 || rawArgs[0] is "--help" or "-h" or "help")
        {
            PrintUsage();
            return 0;
        }

        string cmd = rawArgs[0].ToLowerInvariant();
        var args = rawArgs.Skip(1).ToList();

        string? Option(string name)
        {
            int idx = args.IndexOf(name);
            if (idx >= 0 && idx + 1 < args.Count)
            {
                string val = args[idx + 1];
                args.RemoveAt(idx + 1);
                args.RemoveAt(idx);
                return val;
            }
            return null;
        }

        try
        {
            switch (cmd)
            {
                case "hash":
                    if (args.Count == 0) { PrintUsage(); return 1; }
                    foreach (string f in args)
                    {
                        byte[] data = File.ReadAllBytes(f);
                        var pe = new PEImage(data);
                        Console.WriteLine($"{Convert.ToHexString(pe.Sha256).ToLowerInvariant()}  {f}");
                    }
                    return 0;

                case "inspect":
                    if (args.Count == 0) { PrintUsage(); return 1; }
                    foreach (string f in args)
                    {
                        var status = Inspector.Inspect(f);
                        switch (status)
                        {
                            case FileStatus.NotPEStatus notPe:
                                Console.WriteLine($"{f}: not a PE image ({notPe.Reason})");
                                break;
                            case FileStatus.UnsignedStatus:
                                Console.WriteLine($"{f}: UNSIGNED");
                                break;
                            case FileStatus.AppleFormatStatus:
                                Console.WriteLine($"{f}: Apple EFI signature format (not PKCS#7)");
                                break;
                            case FileStatus.SignedStatus signed:
                                var i = signed.Info;
                                Console.WriteLine($"{f}: {(i.IsValid ? "VALID" : "INVALID")} signer={i.SignerName} issuer={i.IssuerName} alg={i.DigestAlgorithm}");
                                Console.WriteLine($"   digest in sig: {Convert.ToHexString(i.DigestInSignature).ToLowerInvariant()}");
                                Console.WriteLine($"   computed:      {Convert.ToHexString(i.ComputedDigest).ToLowerInvariant()}");
                                if (i.Problems.Count > 0)
                                {
                                    Console.WriteLine($"   problems:      {string.Join("; ", i.Problems)}");
                                }
                                break;
                        }
                    }
                    return 0;

                case "sign":
                    string? key = Option("--key");
                    string? cert = Option("--cert");
                    string? outPath = Option("--out");

                    if (string.IsNullOrEmpty(key) || string.IsNullOrEmpty(cert) || args.Count == 0)
                    {
                        Console.WriteLine("error: --key and --cert are required for signing.");
                        PrintUsage();
                        return 2;
                    }

                    using (var id = SigningIdentity.Load(key, cert))
                    {
                        foreach (string f in args)
                        {
                            byte[] original = File.ReadAllBytes(f);
                            var (signed, hash) = Authenticode.Sign(original, id);
                            string dest = outPath ?? f;
                            File.WriteAllBytes(dest, signed);
                            Console.WriteLine($"signed {dest}  sha256={Convert.ToHexString(hash).ToLowerInvariant()}");
                        }
                    }
                    return 0;

                case "esl":
                    string? eslCert = Option("--cert");
                    string? eslOut = Option("--out");
                    if (string.IsNullOrEmpty(eslCert) || string.IsNullOrEmpty(eslOut))
                    {
                        Console.WriteLine("error: --cert and --out are required for ESL generation.");
                        PrintUsage();
                        return 2;
                    }

                    byte[] certDer = SigningIdentity.ExtractCertificateDer(File.ReadAllBytes(eslCert));
                    byte[] eslBytes = Authenticode.MakeESL(certDer);
                    File.WriteAllBytes(eslOut, eslBytes);
                    Console.WriteLine($"wrote {eslOut} ({eslBytes.Length} bytes)");
                    return 0;

                case "scan":
                    string? trustedCert = Option("--cert");
                    byte[]? trustedDer = null;
                    if (!string.IsNullOrEmpty(trustedCert))
                    {
                        trustedDer = SigningIdentity.ExtractCertificateDer(File.ReadAllBytes(trustedCert));
                    }

                    var mountPoints = args.Count > 0
                        ? args
                        : DiskService.ListEFIPartitions().Where(p => p.IsMounted).Select(p => p.MountPoint!).ToList();

                    if (mountPoints.Count == 0)
                    {
                        Console.WriteLine("No mounted EFI partitions found. Specify a path: efisign scan <path>");
                        return 1;
                    }

                    foreach (string mp in mountPoints)
                    {
                        var (entries, config) = Scanner.Scan(mp, trustedDer);
                        Console.WriteLine($"== {mp}");
                        if (config != null)
                        {
                            Console.WriteLine($"   OpenCore config: SecureBootModel={config.SecureBootModel ?? "?"} Vault={config.Vault ?? "?"} DisableSecurityPolicy={config.DisableSecurityPolicy}");
                            foreach (var w in config.Warnings)
                            {
                                string fixStr = w.Fix != null ? $" [fix: {w.Fix.Title}]" : "";
                                Console.WriteLine($"   ! {w.Message}{fixStr}");
                            }
                        }

                        foreach (var e in entries)
                        {
                            Console.WriteLine($"   {Pad(e.RelativePath, 34)} {Pad(e.Verdict.DisplayName(), 28)} {Pad(e.Role.DisplayName(), 24)} {e.SignerDescription}");
                        }
                    }
                    return 0;

                case "firmware":
                    var fw = FirmwareState.Read();
                    Console.WriteLine(fw.Summary);
                    Console.WriteLine($"Setup mode: {fw.SetupMode?.ToString() ?? "unknown"}");
                    Console.WriteLine($"OpenCore: {fw.OpenCoreVersion ?? "not detected"}");
                    Console.WriteLine($"Apple Secure Boot policy: {fw.AppleSecureBootPolicy?.ToString() ?? "unknown"}");
                    return 0;

                case "disks":
                    var disks = DiskService.ListEFIPartitions();
                    Console.WriteLine($"Found {disks.Count} EFI partition(s) / volume(s):");
                    foreach (var p in disks)
                    {
                        string mp = p.IsMounted ? p.MountPoint! : "not mounted";
                        string flags = $"{(p.IsRemovable ? "[removable] " : "")}{(p.IsInternal ? "[internal] " : "")}";
                        Console.WriteLine($"{Pad(p.Id, 16)} {Pad(p.VolumeName, 16)} {Pad(mp, 20)} {Pad(FormatSize(p.Size), 12)} {p.DiskName} {flags}");
                    }
                    return 0;

                case "strip":
                    if (args.Count == 0) { PrintUsage(); return 1; }
                    foreach (string f in args)
                    {
                        byte[] data = File.ReadAllBytes(f);
                        var pe = new PEImage(data);
                        if (pe.StripSignature())
                        {
                            pe.UpdateChecksum();
                            File.WriteAllBytes(f, pe.Data);
                            Console.WriteLine($"stripped {f}");
                        }
                        else
                        {
                            Console.WriteLine($"{f}: no signature present");
                        }
                    }
                    return 0;

                case "revert":
                    string? backups = Option("--backups");
                    if (string.IsNullOrEmpty(backups) || args.Count == 0)
                    {
                        Console.WriteLine("usage: efisign revert --backups <folder> <mountpoint> [relative/path.efi ...]");
                        return 2;
                    }

                    string rootMp = args[0];
                    var wanted = args.Skip(1).Select(s => s.Replace('\\', '/').ToLowerInvariant()).ToHashSet();

                    var (scanEntries, _) = Scanner.Scan(rootMp, null);
                    foreach (var e in scanEntries.Where(x => wanted.Count == 0 || wanted.Contains(x.RelativePath.ToLowerInvariant())))
                    {
                        var o = RestoreService.Revert(e, [backups]);
                        if (o.Error != null)
                        {
                            Console.WriteLine($"FAILED {e.RelativePath}: {o.Error}");
                        }
                        else
                        {
                            Console.WriteLine($"reverted {e.RelativePath}: {o.Method}");
                        }
                    }
                    return 0;

                case "fix-config":
                    if (args.Count < 2)
                    {
                        Console.WriteLine("usage: efisign fix-config <mountpoint> secure-boot-model|security-policy|disable-tool:<name>");
                        return 2;
                    }

                    string espRoot = args[0];
                    string fixArg = args[1].ToLowerInvariant();

                    ConfigFix fix = fixArg switch
                    {
                        "secure-boot-model" => ConfigFix.SecureBootModelDefault,
                        "security-policy" => ConfigFix.DisableSecurityPolicyOff,
                        _ when fixArg.StartsWith("disable-tool:") => ConfigFix.DisableTool(fixArg["disable-tool:".Length..]),
                        _ => throw new ArgumentException($"Unknown fix: {fixArg}")
                    };

                    OpenCoreConfig.ApplyFix(fix, espRoot, null);
                    Console.WriteLine($"applied: {fix.Title}");
                    return 0;

                default:
                    Console.WriteLine($"unknown command: {cmd}");
                    PrintUsage();
                    return 2;
            }
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"error: {ex.Message}");
            return 1;
        }
    }

    private static string Pad(string s, int n) =>
        s.Length >= n ? s + " " : s + new string(' ', n - s.Length);

    private static string FormatSize(long bytes)
    {
        if (bytes < 1024) return $"{bytes} B";
        if (bytes < 1024 * 1024) return $"{bytes / 1024.0:F1} KB";
        return $"{bytes / (1024.0 * 1024.0):F1} MB";
    }

    private static void PrintUsage()
    {
        Console.WriteLine("""
        EFI Signer CLI (SelfSecureBoot):
          usage:
            SelfSecureBoot hash <file.efi>
            SelfSecureBoot inspect <file.efi>...
            SelfSecureBoot sign --key db.key --cert db.crt [--out out.efi] <file.efi>...
            SelfSecureBoot esl --cert db.crt --out db.esl
            SelfSecureBoot scan [mountpoint] [--cert db.crt]
            SelfSecureBoot firmware
            SelfSecureBoot disks
            SelfSecureBoot strip <file.efi>...
            SelfSecureBoot revert --backups <folder> <mountpoint> [relative/path.efi ...]
            SelfSecureBoot fix-config <mountpoint> secure-boot-model|security-policy|disable-tool:<name>
            SelfSecureBoot --test
        """);
    }
}

