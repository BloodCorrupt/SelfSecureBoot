using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace SelfSecureBoot.Core;

public sealed record EFIPartition
{
    public string Id { get; init; } = "";
    public int DiskNumber { get; init; }
    public int PartitionNumber { get; init; }
    public string VolumeName { get; init; } = "EFI";
    public string? MountPoint { get; init; }
    public long Size { get; init; }
    public string DiskName { get; init; } = "Disk";
    public bool IsInternal { get; init; } = true;
    public bool IsRemovable { get; init; }
    public string? PartitionUUID { get; init; }
    public bool IsMounted => !string.IsNullOrEmpty(MountPoint);
}

public static class DiskService
{
    public static bool IsElevated
    {
        get
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                using var identity = WindowsIdentity.GetCurrent();
                var principal = new WindowsPrincipal(identity);
                return principal.IsInRole(WindowsBuiltInRole.Administrator);
            }
            else
            {
                return geteuid() == 0;
            }
        }
    }

    [DllImport("libc", SetLastError = true)]
    private static extern uint geteuid();

    public static bool RelaunchAsElevated(string? arguments = null)
    {
        try
        {
            string? exe = Environment.ProcessPath;
            if (string.IsNullOrEmpty(exe)) return false;

            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                var psi = new ProcessStartInfo
                {
                    FileName = exe,
                    Arguments = arguments ?? "",
                    Verb = "runas",
                    UseShellExecute = true
                };
                Process.Start(psi);
                Environment.Exit(0);
                return true;
            }
            else
            {
                // Linux: pkexec or sudo
                string runner = File.Exists("/usr/bin/pkexec") ? "/usr/bin/pkexec" : "sudo";
                var psi = new ProcessStartInfo
                {
                    FileName = runner,
                    Arguments = $"\"{exe}\" {arguments ?? ""}",
                    UseShellExecute = false
                };
                Process.Start(psi);
                Environment.Exit(0);
                return true;
            }
        }
        catch
        {
            return false;
        }
    }

    public static List<EFIPartition> ListEFIPartitions()
    {
        var list = new List<EFIPartition>();

        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            list.AddRange(ListWindowsPartitions());
        }
        else if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
        {
            list.AddRange(ListLinuxPartitions());
        }

        // Always check accessible logical drive volumes for FAT32 / EFI folders (e.g. USB sticks)
        try
        {
            foreach (var drive in DriveInfo.GetDrives())
            {
                if (!drive.IsReady) continue;

                string root = drive.RootDirectory.FullName;
                bool hasEfi = Directory.Exists(Path.Combine(root, "EFI")) ||
                              Directory.Exists(Path.Combine(root, "efi"));

                // If already detected, don't duplicate
                if (list.Any(p => !string.IsNullOrEmpty(p.MountPoint) &&
                                  string.Equals(p.MountPoint.TrimEnd('\\', '/'), root.TrimEnd('\\', '/'), StringComparison.OrdinalIgnoreCase)))
                {
                    continue;
                }

                if (hasEfi || drive.DriveType == DriveType.Removable)
                {
                    string label = string.IsNullOrWhiteSpace(drive.VolumeLabel) ? "EFI Volume" : drive.VolumeLabel;
                    list.Add(new EFIPartition
                    {
                        Id = $"Drive {drive.Name.TrimEnd('\\')}",
                        DiskNumber = -1,
                        PartitionNumber = -1,
                        VolumeName = label,
                        MountPoint = root,
                        Size = drive.TotalSize,
                        DiskName = $"{drive.DriveType} Drive ({drive.DriveFormat})",
                        IsInternal = drive.DriveType == DriveType.Fixed,
                        IsRemovable = drive.DriveType == DriveType.Removable,
                        PartitionUUID = null
                    });
                }
            }
        }
        catch { }

        return list;
    }

    private sealed class WinPartitionJson
    {
        [JsonPropertyName("DiskNumber")]
        public int DiskNumber { get; set; }

        [JsonPropertyName("PartitionNumber")]
        public int PartitionNumber { get; set; }

        [JsonPropertyName("DriveLetter")]
        public object? DriveLetter { get; set; }

        [JsonPropertyName("GptType")]
        public string? GptType { get; set; }

        [JsonPropertyName("Type")]
        public string? Type { get; set; }

        [JsonPropertyName("Size")]
        public long Size { get; set; }
    }

    private sealed class WinDiskJson
    {
        [JsonPropertyName("Number")]
        public int Number { get; set; }

        [JsonPropertyName("FriendlyName")]
        public string? FriendlyName { get; set; }

        [JsonPropertyName("BusType")]
        public string? BusType { get; set; }
    }

    private static List<EFIPartition> ListWindowsPartitions()
    {
        var result = new List<EFIPartition>();
        try
        {
            // 1. Query physical disks
            var diskMap = new Dictionary<int, (string Name, bool IsRemovable)>();
            try
            {
                string diskCmd = "Get-Disk | Select-Object Number, FriendlyName, BusType | ConvertTo-Json";
                string diskJson = RunPowerShell(diskCmd);
                if (!string.IsNullOrWhiteSpace(diskJson))
                {
                    if (diskJson.TrimStart().StartsWith("["))
                    {
                        var disks = JsonSerializer.Deserialize<List<WinDiskJson>>(diskJson);
                        if (disks != null)
                        {
                            foreach (var d in disks)
                            {
                                bool isRemovable = string.Equals(d.BusType, "USB", StringComparison.OrdinalIgnoreCase);
                                diskMap[d.Number] = (d.FriendlyName ?? $"Disk {d.Number}", isRemovable);
                            }
                        }
                    }
                    else
                    {
                        var d = JsonSerializer.Deserialize<WinDiskJson>(diskJson);
                        if (d != null)
                        {
                            bool isRemovable = string.Equals(d.BusType, "USB", StringComparison.OrdinalIgnoreCase);
                            diskMap[d.Number] = (d.FriendlyName ?? $"Disk {d.Number}", isRemovable);
                        }
                    }
                }
            }
            catch { }

            // 2. Query partitions for EFI ESP Guid {c12a7328-f81f-11d2-ba4b-00a0c93ec93b} or Type System
            string partCmd = "Get-Partition | Where-Object { $_.GptType -eq '{c12a7328-f81f-11d2-ba4b-00a0c93ec93b}' -or $_.Type -eq 'System' } | Select-Object DiskNumber, PartitionNumber, DriveLetter, GptType, Type, Size | ConvertTo-Json";
            string partJson = RunPowerShell(partCmd);

            if (!string.IsNullOrWhiteSpace(partJson))
            {
                List<WinPartitionJson> parts = [];
                if (partJson.TrimStart().StartsWith("["))
                {
                    parts = JsonSerializer.Deserialize<List<WinPartitionJson>>(partJson) ?? [];
                }
                else
                {
                    var single = JsonSerializer.Deserialize<WinPartitionJson>(partJson);
                    if (single != null) parts.Add(single);
                }

                foreach (var p in parts)
                {
                    string id = $"Disk {p.DiskNumber} Part {p.PartitionNumber}";
                    string? driveLetter = null;
                    if (p.DriveLetter != null)
                    {
                        string dlStr = p.DriveLetter.ToString()?.Trim() ?? "";
                        if (!string.IsNullOrEmpty(dlStr) && dlStr != "\0" && dlStr != "0")
                        {
                            driveLetter = dlStr.Length == 1 ? $"{dlStr}:\\" : dlStr;
                        }
                    }

                    var (diskName, isRemovable) = diskMap.TryGetValue(p.DiskNumber, out var info)
                        ? info
                        : ($"Physical Disk {p.DiskNumber}", false);

                    result.Add(new EFIPartition
                    {
                        Id = id,
                        DiskNumber = p.DiskNumber,
                        PartitionNumber = p.PartitionNumber,
                        VolumeName = "EFI System Partition",
                        MountPoint = driveLetter,
                        Size = p.Size,
                        DiskName = diskName,
                        IsInternal = !isRemovable,
                        IsRemovable = isRemovable,
                        PartitionUUID = null
                    });
                }
            }
        }
        catch { }

        return result;
    }

    private static List<EFIPartition> ListLinuxPartitions()
    {
        var result = new List<EFIPartition>();
        try
        {
            // Run lsblk -J -b -o NAME,PARTTYPE,MOUNTPOINT,LABEL,SIZE,UUID,FSTYPE,RM,MODEL
            var psi = new ProcessStartInfo
            {
                FileName = "lsblk",
                Arguments = "-J -b -o NAME,PARTTYPE,MOUNTPOINT,LABEL,SIZE,UUID,FSTYPE,RM,MODEL",
                RedirectStandardOutput = true,
                UseShellExecute = false
            };
            using var proc = Process.Start(psi);
            if (proc != null)
            {
                string json = proc.StandardOutput.ReadToEnd();
                proc.WaitForExit();

                using var doc = JsonDocument.Parse(json);
                if (doc.RootElement.TryGetProperty("blockdevices", out var devices))
                {
                    TraverseLinuxDevices(devices, null, result);
                }
            }
        }
        catch { }

        return result;
    }

    private static void TraverseLinuxDevices(JsonElement devices, string? parentModel, List<EFIPartition> result)
    {
        foreach (var dev in devices.EnumerateArray())
        {
            string name = dev.TryGetProperty("name", out var n) ? n.GetString() ?? "" : "";
            string partType = dev.TryGetProperty("parttype", out var pt) ? pt.GetString() ?? "" : "";
            string mountPoint = dev.TryGetProperty("mountpoint", out var mp) ? mp.GetString() ?? "" : "";
            string label = dev.TryGetProperty("label", out var l) ? l.GetString() ?? "" : "";
            long size = dev.TryGetProperty("size", out var s) && s.TryGetInt64(out long sz) ? sz : 0;
            string uuid = dev.TryGetProperty("uuid", out var u) ? u.GetString() ?? "" : "";
            string model = dev.TryGetProperty("model", out var m) ? m.GetString() ?? "" : parentModel ?? "Block Device";
            bool isRemovable = dev.TryGetProperty("rm", out var rm) && (rm.GetString() == "1" || rm.GetInt32() == 1);

            bool isEfi = string.Equals(partType, "c12a7328-f81f-11d2-ba4b-00a0c93ec93b", StringComparison.OrdinalIgnoreCase) ||
                         string.Equals(mountPoint, "/boot/efi", StringComparison.OrdinalIgnoreCase) ||
                         string.Equals(label, "EFI", StringComparison.OrdinalIgnoreCase);

            if (isEfi)
            {
                result.Add(new EFIPartition
                {
                    Id = $"/dev/{name}",
                    DiskNumber = 0,
                    PartitionNumber = 0,
                    VolumeName = string.IsNullOrEmpty(label) ? "EFI" : label,
                    MountPoint = string.IsNullOrEmpty(mountPoint) ? null : mountPoint,
                    Size = size,
                    DiskName = model,
                    IsInternal = !isRemovable,
                    IsRemovable = isRemovable,
                    PartitionUUID = uuid
                });
            }

            if (dev.TryGetProperty("children", out var children))
            {
                TraverseLinuxDevices(children, model, result);
            }
        }
    }

    [DllImport("kernel32.dll")]
    private static extern uint GetLogicalDrives();

    public static HashSet<char> GetUsedDriveLetters()
    {
        var used = new HashSet<char>();

        try
        {
            foreach (var d in Directory.GetLogicalDrives())
            {
                if (!string.IsNullOrEmpty(d))
                {
                    used.Add(char.ToUpperInvariant(d[0]));
                }
            }
        }
        catch { }

        try
        {
            foreach (var drive in DriveInfo.GetDrives())
            {
                if (!string.IsNullOrEmpty(drive.Name))
                {
                    used.Add(char.ToUpperInvariant(drive.Name[0]));
                }
            }
        }
        catch { }

        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            try
            {
                uint mask = GetLogicalDrives();
                for (int i = 0; i < 26; i++)
                {
                    if ((mask & (1U << i)) != 0)
                    {
                        used.Add((char)('A' + i));
                    }
                }
            }
            catch { }
        }

        return used;
    }

    public static List<char> GetAvailableDriveLetters()
    {
        var used = GetUsedDriveLetters();

        // Prefer standard safe system/EFI letters: S, Y, X, W, V, U, T, R, Q, P, M, L, K, J, I, H, F, E
        char[] preferred = ['S', 'Y', 'X', 'W', 'V', 'U', 'T', 'R', 'Q', 'P', 'M', 'L', 'K', 'J', 'I', 'H', 'F', 'E'];
        var available = preferred.Where(c => !used.Contains(c)).ToList();

        // Add any remaining unused letters between D and Z
        for (char c = 'Z'; c >= 'D'; c--)
        {
            if (!used.Contains(c) && !available.Contains(c))
            {
                available.Add(c);
            }
        }

        return available;
    }

    public static char FindFreeDriveLetter(char? preferredLetter = null)
    {
        var available = GetAvailableDriveLetters();
        if (preferredLetter.HasValue)
        {
            char up = char.ToUpperInvariant(preferredLetter.Value);
            if (available.Contains(up)) return up;
        }

        return available.Count > 0 ? available[0] : 'S';
    }

    public static string Mount(EFIPartition partition, char? chosenLetter = null)
    {
        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            if (!IsElevated)
            {
                throw new UnauthorizedAccessException("Mounting EFI system partitions requires Administrator privileges. Please launch as Administrator.");
            }

            char letterToUse = chosenLetter.HasValue ? char.ToUpperInvariant(chosenLetter.Value) : FindFreeDriveLetter();
            var used = GetUsedDriveLetters();
            if (used.Contains(letterToUse))
            {
                char fallback = FindFreeDriveLetter();
                letterToUse = fallback;
            }

            string accessPath = $"{letterToUse}:\\";

            if (partition.DiskNumber >= 0 && partition.PartitionNumber >= 0)
            {
                // Method 1: Add-PartitionAccessPath
                try
                {
                    string script = $"Add-PartitionAccessPath -DiskNumber {partition.DiskNumber} -PartitionNumber {partition.PartitionNumber} -AccessPath '{accessPath}'";
                    RunPowerShell(script);
                    if (Directory.Exists(accessPath)) return accessPath;
                }
                catch { }

                // Method 2: Diskpart script
                try
                {
                    string dpScript = $"select disk {partition.DiskNumber}\r\nselect partition {partition.PartitionNumber}\r\nassign letter={letterToUse}\r\n";
                    string tempFile = Path.GetTempFileName();
                    File.WriteAllText(tempFile, dpScript);

                    var psi = new ProcessStartInfo("diskpart.exe", $"/s \"{tempFile}\"")
                    {
                        CreateNoWindow = true,
                        UseShellExecute = false,
                        RedirectStandardOutput = true
                    };
                    using var p = Process.Start(psi);
                    p?.WaitForExit();
                    try { File.Delete(tempFile); } catch { }

                    if (Directory.Exists(accessPath)) return accessPath;
                }
                catch { }

                // Method 3: mountvol /S (for system ESP)
                try
                {
                    var psi = new ProcessStartInfo("mountvol.exe", $"{letterToUse}: /S")
                    {
                        CreateNoWindow = true,
                        UseShellExecute = false
                    };
                    using var p = Process.Start(psi);
                    p?.WaitForExit();

                    if (Directory.Exists(accessPath)) return accessPath;
                }
                catch { }

                throw new InvalidOperationException($"Could not mount partition to {accessPath}. Ensure partition is not locked by another process.");
            }

            throw new InvalidOperationException("Partition does not have valid disk and partition indices for mounting.");
        }
        else
        {
            // Linux mount
            string mountDir = $"/mnt/efi_{Path.GetFileName(partition.Id)}";
            Directory.CreateDirectory(mountDir);

            var psi = new ProcessStartInfo("mount", $"{partition.Id} {mountDir}")
            {
                UseShellExecute = false
            };
            using var p = Process.Start(psi);
            p?.WaitForExit();
            if (p?.ExitCode != 0)
            {
                throw new InvalidOperationException($"Failed to mount {partition.Id} to {mountDir}. Ensure running with sudo.");
            }

            return mountDir;
        }
    }

    public static void Unmount(EFIPartition partition)
    {
        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            if (string.IsNullOrEmpty(partition.MountPoint)) return;

            char letter = partition.MountPoint.TrimEnd('\\', '/')[0];

            // Method 1: Remove-PartitionAccessPath
            if (partition.DiskNumber >= 0 && partition.PartitionNumber >= 0)
            {
                try
                {
                    string script = $"Remove-PartitionAccessPath -DiskNumber {partition.DiskNumber} -PartitionNumber {partition.PartitionNumber} -AccessPath '{letter}:\\'";
                    RunPowerShell(script);
                    return;
                }
                catch { }
            }

            // Method 2: mountvol /D
            try
            {
                var psi = new ProcessStartInfo("mountvol.exe", $"{letter}: /D")
                {
                    CreateNoWindow = true,
                    UseShellExecute = false
                };
                using var p = Process.Start(psi);
                p?.WaitForExit();
            }
            catch { }
        }
        else
        {
            if (string.IsNullOrEmpty(partition.MountPoint)) return;
            var psi = new ProcessStartInfo("umount", partition.MountPoint)
            {
                UseShellExecute = false
            };
            using var p = Process.Start(psi);
            p?.WaitForExit();
        }
    }

    private static string RunPowerShell(string script)
    {
        var psi = new ProcessStartInfo
        {
            FileName = "powershell.exe",
            Arguments = $"-NoProfile -NonInteractive -Command \"{script}\"",
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true
        };

        using var proc = Process.Start(psi);
        if (proc == null) return "";

        string output = proc.StandardOutput.ReadToEnd();
        proc.WaitForExit();
        return output;
    }
}

