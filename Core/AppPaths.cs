using System;
using System.IO;
using System.Runtime.InteropServices;

namespace SelfSecureBoot.Core;

public static class AppPaths
{
    public const string AppName = "EFISigner";

    public static string DataDir { get; } = ResolveDataDir();

    public static void EnsureDirectories()
    {
        Directory.CreateDirectory(DataDir);
    }

    private static string ResolveDataDir()
    {
        string path;
        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            path = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), AppName);
        }
        else if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
        {
            path = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
                "Library", "Application Support", "EFI Signer");
        }
        else
        {
            string xdg = Environment.GetEnvironmentVariable("XDG_CONFIG_HOME")
                       ?? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".config");
            path = Path.Combine(xdg, AppName);
        }

        Directory.CreateDirectory(path);
        return path;
    }
}

