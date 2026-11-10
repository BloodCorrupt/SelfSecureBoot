using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32;

namespace SelfSecureBoot.Core;

public sealed class FirmwareState
{
    public bool? SecureBootEnabled { get; set; }
    public bool? SetupMode { get; set; }
    public string? OpenCoreVersion { get; set; }
    public int? AppleSecureBootPolicy { get; set; }
    public bool IsHackintosh => !string.IsNullOrEmpty(OpenCoreVersion);

    public string Summary
    {
        get
        {
            return SecureBootEnabled switch
            {
                true => SetupMode == true
                    ? "UEFI Secure Boot: on, but firmware is in Setup Mode"
                    : "UEFI Secure Boot: enforced",
                false => "UEFI Secure Boot: off",
                null => "UEFI Secure Boot: unknown (variable not exposed)"
            };
        }
    }

    public const string EfiGlobalGuid = "{8be4df61-93ca-11d2-aa0d-00e098032b8c}";
    public const string OpenCoreGuid = "{4d1fda02-38c7-4a6a-9cc6-4bcca8b30102}";
    public const string AppleGuid = "{94b73556-2197-4702-82a8-3e1337dafbfb}";

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern uint GetFirmwareEnvironmentVariableW(string lpName, string lpGuid, byte[] pBuffer, uint nSize);

    public static FirmwareState Read()
    {
        var state = new FirmwareState();

        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            ReadWindowsState(state);
        }
        else if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
        {
            ReadLinuxState(state);
        }

        return state;
    }

    private static void ReadWindowsState(FirmwareState state)
    {
        // 1. Registry query (works without elevation)
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\SecureBoot\State");
            if (key != null)
            {
                var val = key.GetValue("UEFISecureBootEnabled");
                if (val is int intVal)
                {
                    state.SecureBootEnabled = (intVal == 1);
                }
            }
        }
        catch { }

        // 2. Win32 Firmware Variables
        byte[] buf = new byte[256];

        // Check SecureBoot variable if not found yet
        if (!state.SecureBootEnabled.HasValue)
        {
            uint len = GetFirmwareEnvironmentVariableW("SecureBoot", EfiGlobalGuid, buf, 256);
            if (len > 0)
            {
                state.SecureBootEnabled = (buf[0] == 1);
            }
        }

        // Check SetupMode
        uint smLen = GetFirmwareEnvironmentVariableW("SetupMode", EfiGlobalGuid, buf, 256);
        if (smLen > 0)
        {
            state.SetupMode = (buf[0] == 1);
        }

        // Check OpenCore version
        uint ocLen = GetFirmwareEnvironmentVariableW("opencore-version", OpenCoreGuid, buf, 256);
        if (ocLen > 0)
        {
            int strLen = 0;
            while (strLen < ocLen && buf[strLen] != 0) strLen++;
            state.OpenCoreVersion = Encoding.ASCII.GetString(buf, 0, strLen);
        }

        // Check AppleSecureBootPolicy
        uint apLen = GetFirmwareEnvironmentVariableW("AppleSecureBootPolicy", AppleGuid, buf, 256);
        if (apLen > 0)
        {
            state.AppleSecureBootPolicy = (int)buf[0];
        }
    }

    private static void ReadLinuxState(FirmwareState state)
    {
        string efiVars = "/sys/firmware/efi/efivars";
        if (!Directory.Exists(efiVars)) return;

        // In Linux efivars, the first 4 bytes are variable attributes, 5th byte starts data
        try
        {
            string sbPath = Path.Combine(efiVars, "SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c");
            if (File.Exists(sbPath))
            {
                byte[] data = File.ReadAllBytes(sbPath);
                if (data.Length >= 5) state.SecureBootEnabled = (data[4] == 1);
            }

            string smPath = Path.Combine(efiVars, "SetupMode-8be4df61-93ca-11d2-aa0d-00e098032b8c");
            if (File.Exists(smPath))
            {
                byte[] data = File.ReadAllBytes(smPath);
                if (data.Length >= 5) state.SetupMode = (data[4] == 1);
            }

            string ocPath = Path.Combine(efiVars, "opencore-version-4d1fda02-38c7-4a6a-9cc6-4bcca8b30102");
            if (File.Exists(ocPath))
            {
                byte[] data = File.ReadAllBytes(ocPath);
                if (data.Length > 4)
                {
                    int end = 4;
                    while (end < data.Length && data[end] != 0) end++;
                    state.OpenCoreVersion = Encoding.ASCII.GetString(data, 4, end - 4);
                }
            }
        }
        catch { }
    }
}

