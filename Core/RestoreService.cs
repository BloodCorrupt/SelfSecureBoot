using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace SelfSecureBoot.Core;

public sealed record RestoreOutcome(EFIFileEntry Entry, string? Method, string? Error);

public static class RestoreService
{
    public static RestoreOutcome Revert(EFIFileEntry entry, List<string> backupFolders)
    {
        // 1. Check backup folders for original copy
        foreach (string folder in backupFolders)
        {
            string src = Path.Combine(folder, entry.RelativePath);
            if (File.Exists(src))
            {
                try
                {
                    byte[] data = File.ReadAllBytes(src);
                    _ = new PEImage(data); // Refuse to restore invalid PE garbage over bootloader
                    File.WriteAllBytes(entry.FullPath, data);
                    return new RestoreOutcome(entry, $"Restored from backup {Path.GetFileName(folder)}", null);
                }
                catch (Exception ex)
                {
                    return new RestoreOutcome(entry, null, ex.Message);
                }
            }
        }

        // 2. No backup exists: strip signature in place if signed
        try
        {
            byte[] currentBytes = File.ReadAllBytes(entry.FullPath);
            var pe = new PEImage(currentBytes);
            if (!pe.StripSignature())
            {
                return new RestoreOutcome(entry, null, "No backup found and the file carries no signature");
            }

            pe.UpdateChecksum();
            File.WriteAllBytes(entry.FullPath, pe.Data);
            return new RestoreOutcome(entry, "Signature removed (no backup found)", null);
        }
        catch (Exception ex)
        {
            return new RestoreOutcome(entry, null, ex.Message);
        }
    }

    public static List<string> GetConfigBackups(List<string> backupFolders)
    {
        var list = new List<string>();
        foreach (string folder in backupFolders)
        {
            string dir = Path.Combine(folder, "EFI", "OC");
            if (Directory.Exists(dir))
            {
                var files = Directory.GetFiles(dir, "config.plist.*.bak")
                                     .OrderBy(f => f);
                list.AddRange(files);
            }
        }
        return list;
    }

    public static string RestoreConfig(string espRoot, List<string> backupFolders)
    {
        var backups = GetConfigBackups(backupFolders);
        if (backups.Count == 0)
            throw new FileNotFoundException("No config.plist backup found in backup history");

        string oldest = backups[0];
        string? currentConfig = OpenCoreConfig.FindConfigPath(espRoot);
        if (currentConfig == null)
            throw new FileNotFoundException("Current config.plist not found in ESP root");

        // Save current config before reverting
        string timestamp = DateTime.Now.ToString("yyyyMMdd-HHmmss-fff");
        string backupDir = Path.GetDirectoryName(oldest)!;
        string newBackup = Path.Combine(backupDir, $"config.plist.{timestamp}.bak");
        File.Copy(currentConfig, newBackup, overwrite: true);

        // Copy oldest backup back
        File.Copy(oldest, currentConfig, overwrite: true);

        return Path.GetFileName(oldest);
    }
}
