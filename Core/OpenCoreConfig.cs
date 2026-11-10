using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Xml.Linq;

namespace SelfSecureBoot.Core;

public abstract record ConfigFix
{
    public sealed record SecureBootModelDefaultFix : ConfigFix
    {
        public override string Title => "Set SecureBootModel to Default";
        public override string Explanation =>
            "Sets Misc > Security > SecureBootModel to Default, so OpenCore runs Apple Secure Boot at Medium security " +
            "and loads macOS boot.efi through its own verified loader. Reboot once with UEFI Secure Boot still off " +
            "to confirm macOS and all your kexts still load before enabling it in the BIOS.";
    }

    public sealed record DisableSecurityPolicyOffFix : ConfigFix
    {
        public override string Title => "Set DisableSecurityPolicy to false";
        public override string Explanation =>
            "Sets UEFI > Quirks > DisableSecurityPolicy to false. That quirk switches off the firmware's own security " +
            "features and defeats Secure Boot.";
    }

    public sealed record DisableToolFix(string ToolName) : ConfigFix
    {
        public override string Title => $"Disable {ToolName}";
        public override string Explanation =>
            $"Sets Enabled to false on the {ToolName} entry under Misc > Tools. A UEFI shell started from the boot " +
            "picker could load anything, which bypasses the Secure Boot chain.";
    }

    public abstract string Title { get; }
    public abstract string Explanation { get; }

    public static ConfigFix SecureBootModelDefault => new SecureBootModelDefaultFix();
    public static ConfigFix DisableSecurityPolicyOff => new DisableSecurityPolicyOffFix();
    public static ConfigFix DisableTool(string toolName) => new DisableToolFix(toolName);
}

public sealed record ConfigWarning(string Message, ConfigFix? Fix);

public sealed class OpenCoreConfig
{
    public string? SecureBootModel { get; set; }
    public string? DmgLoading { get; set; }
    public string? Vault { get; set; }
    public bool DisableSecurityPolicy { get; set; }
    public HashSet<string> EnabledDrivers { get; } = new(StringComparer.OrdinalIgnoreCase);
    public HashSet<string> DisabledDrivers { get; } = new(StringComparer.OrdinalIgnoreCase);
    public HashSet<string> EnabledTools { get; } = new(StringComparer.OrdinalIgnoreCase);
    public HashSet<string> DisabledTools { get; } = new(StringComparer.OrdinalIgnoreCase);
    public List<ConfigWarning> Warnings { get; } = new();

    public static string? FindConfigPath(string espRoot)
    {
        string[] candidates =
        [
            Path.Combine(espRoot, "EFI", "OC", "config.plist"),
            Path.Combine(espRoot, "efi", "oc", "config.plist"),
            Path.Combine(espRoot, "OC", "config.plist"),
            Path.Combine(espRoot, "oc", "config.plist")
        ];

        foreach (var c in candidates)
        {
            if (File.Exists(c)) return c;
        }

        return null;
    }

    public static OpenCoreConfig? Load(string espRoot)
    {
        string? configPath = FindConfigPath(espRoot);
        if (configPath == null) return null;

        try
        {
            var doc = XDocument.Load(configPath);
            var rootDict = doc.Root?.Element("dict");
            if (rootDict == null) return null;

            var config = new OpenCoreConfig();

            var miscDict = GetDictValue(rootDict, "Misc");
            if (miscDict != null)
            {
                var secDict = GetDictValue(miscDict, "Security");
                if (secDict != null)
                {
                    config.SecureBootModel = GetStringValue(secDict, "SecureBootModel");
                    config.DmgLoading = GetStringValue(secDict, "DmgLoading");
                    config.Vault = GetStringValue(secDict, "Vault");
                }

                var toolsArray = GetArrayValue(miscDict, "Tools");
                if (toolsArray != null)
                {
                    foreach (var toolDict in toolsArray.Elements("dict"))
                    {
                        string? path = GetStringValue(toolDict, "Path");
                        if (!string.IsNullOrEmpty(path))
                        {
                            bool enabled = GetBoolValue(toolDict, "Enabled") ?? false;
                            if (enabled) config.EnabledTools.Add(path);
                            else config.DisabledTools.Add(path);
                        }
                    }
                }
            }

            var uefiDict = GetDictValue(rootDict, "UEFI");
            if (uefiDict != null)
            {
                var quirksDict = GetDictValue(uefiDict, "Quirks");
                if (quirksDict != null)
                {
                    config.DisableSecurityPolicy = GetBoolValue(quirksDict, "DisableSecurityPolicy") ?? false;
                }

                var driversArray = GetArrayValue(uefiDict, "Drivers");
                if (driversArray != null)
                {
                    foreach (var driverElem in driversArray.Elements())
                    {
                        if (driverElem.Name == "string")
                        {
                            // Older OpenCore format where Drivers is array of strings
                            config.EnabledDrivers.Add(driverElem.Value.Trim());
                        }
                        else if (driverElem.Name == "dict")
                        {
                            string? path = GetStringValue(driverElem, "Path");
                            if (!string.IsNullOrEmpty(path))
                            {
                                bool enabled = GetBoolValue(driverElem, "Enabled") ?? false;
                                if (enabled) config.EnabledDrivers.Add(path);
                                else config.DisabledDrivers.Add(path);
                            }
                        }
                    }
                }
            }

            // Checks and Warnings
            if (string.Equals(config.SecureBootModel, "Disabled", StringComparison.OrdinalIgnoreCase))
            {
                config.Warnings.Add(new ConfigWarning(
                    "SecureBootModel is Disabled: with UEFI Secure Boot on, OpenCore hands macOS boot.efi to the firmware, which will reject it. Set it to Default.",
                    ConfigFix.SecureBootModelDefault));
            }

            if (config.DisableSecurityPolicy)
            {
                config.Warnings.Add(new ConfigWarning(
                    "UEFI > Quirks > DisableSecurityPolicy is true, which defeats Secure Boot. Set it to false.",
                    ConfigFix.DisableSecurityPolicyOff));
            }

            foreach (var shell in new[] { "openshell.efi", "shell.efi" })
            {
                if (config.EnabledTools.Contains(shell))
                {
                    config.Warnings.Add(new ConfigWarning(
                        $"{shell} is enabled as a tool. OpenCore's docs say not to ship a UEFI shell under Secure Boot, since it bypasses the boot chain.",
                        ConfigFix.DisableTool(shell)));
                }
            }

            return config;
        }
        catch
        {
            return null;
        }
    }

    public bool? IsLoaded(string relativePath)
    {
        string lower = relativePath.Replace('\\', '/').ToLowerInvariant();

        if (lower.StartsWith("efi/oc/drivers/"))
        {
            string name = lower["efi/oc/drivers/".Length..];
            if (EnabledDrivers.Contains(name))  return true;
            if (DisabledDrivers.Contains(name)) return false;
            return null; // Not listed in config at all — treat as unknown (signable)
        }

        if (lower.StartsWith("efi/oc/tools/"))
        {
            string name = lower["efi/oc/tools/".Length..];
            if (EnabledTools.Contains(name))  return true;
            if (DisabledTools.Contains(name)) return false;
            return null;
        }

        return null;
    }

    public static void ApplyFix(ConfigFix fix, string espRoot, string? backupRoot)
    {
        string? configPath = FindConfigPath(espRoot);
        if (configPath == null) throw new FileNotFoundException("config.plist not found in ESP root");

        // Backup original file first (oldest backup preserved)
        if (!string.IsNullOrEmpty(backupRoot))
        {
            string time = DateTime.Now.ToString("yyyyMMdd-HHmmss-fff");
            string backupDir = Path.Combine(backupRoot, "EFI", "OC");
            Directory.CreateDirectory(backupDir);
            string backupFile = Path.Combine(backupDir, $"config.plist.{time}.bak");
            if (!File.Exists(backupFile))
            {
                File.Copy(configPath, backupFile);
            }
        }

        var doc = XDocument.Load(configPath);
        var rootDict = doc.Root?.Element("dict");
        if (rootDict == null) throw new FormatException("Invalid config.plist: root dict missing");

        switch (fix)
        {
            case ConfigFix.SecureBootModelDefaultFix:
                var misc = EnsureDictValue(rootDict, "Misc");
                var sec = EnsureDictValue(misc, "Security");
                SetStringValue(sec, "SecureBootModel", "Default");
                break;

            case ConfigFix.DisableSecurityPolicyOffFix:
                var uefi = EnsureDictValue(rootDict, "UEFI");
                var quirks = EnsureDictValue(uefi, "Quirks");
                SetBoolValue(quirks, "DisableSecurityPolicy", false);
                break;

            case ConfigFix.DisableToolFix toolFix:
                var miscTools = EnsureDictValue(rootDict, "Misc");
                var toolsArray = GetArrayValue(miscTools, "Tools");
                if (toolsArray != null)
                {
                    foreach (var tDict in toolsArray.Elements("dict"))
                    {
                        string? path = GetStringValue(tDict, "Path");
                        if (string.Equals(path, toolFix.ToolName, StringComparison.OrdinalIgnoreCase))
                        {
                            SetBoolValue(tDict, "Enabled", false);
                        }
                    }
                }
                break;
        }

        doc.Save(configPath);
    }

    #region XML Plist Traversal Helpers

    public static XElement? GetDictValue(XElement dict, string keyName)
    {
        var keyElem = dict.Elements("key").FirstOrDefault(k => string.Equals(k.Value.Trim(), keyName, StringComparison.OrdinalIgnoreCase));
        if (keyElem == null) return null;
        return keyElem.ElementsAfterSelf().FirstOrDefault(e => e.Name == "dict");
    }

    public static XElement EnsureDictValue(XElement dict, string keyName)
    {
        var existing = GetDictValue(dict, keyName);
        if (existing != null) return existing;

        var keyElem = new XElement("key", keyName);
        var newDict = new XElement("dict");
        dict.Add(keyElem);
        dict.Add(newDict);
        return newDict;
    }

    public static XElement? GetArrayValue(XElement dict, string keyName)
    {
        var keyElem = dict.Elements("key").FirstOrDefault(k => string.Equals(k.Value.Trim(), keyName, StringComparison.OrdinalIgnoreCase));
        if (keyElem == null) return null;
        return keyElem.ElementsAfterSelf().FirstOrDefault(e => e.Name == "array");
    }

    public static string? GetStringValue(XElement dict, string keyName)
    {
        var keyElem = dict.Elements("key").FirstOrDefault(k => string.Equals(k.Value.Trim(), keyName, StringComparison.OrdinalIgnoreCase));
        if (keyElem == null) return null;
        var next = keyElem.ElementsAfterSelf().FirstOrDefault();
        return next?.Name == "string" ? next.Value.Trim() : null;
    }

    public static bool? GetBoolValue(XElement dict, string keyName)
    {
        var keyElem = dict.Elements("key").FirstOrDefault(k => string.Equals(k.Value.Trim(), keyName, StringComparison.OrdinalIgnoreCase));
        if (keyElem == null) return null;
        var next = keyElem.ElementsAfterSelf().FirstOrDefault();
        if (next == null) return null;
        if (next.Name == "true") return true;
        if (next.Name == "false") return false;
        return null;
    }

    public static void SetStringValue(XElement dict, string keyName, string value)
    {
        var keyElem = dict.Elements("key").FirstOrDefault(k => string.Equals(k.Value.Trim(), keyName, StringComparison.OrdinalIgnoreCase));
        if (keyElem != null)
        {
            var next = keyElem.ElementsAfterSelf().FirstOrDefault();
            if (next != null && next.Name == "string")
            {
                next.Value = value;
                return;
            }
            if (next != null)
            {
                next.ReplaceWith(new XElement("string", value));
                return;
            }
        }

        dict.Add(new XElement("key", keyName));
        dict.Add(new XElement("string", value));
    }

    public static void SetBoolValue(XElement dict, string keyName, bool value)
    {
        var keyElem = dict.Elements("key").FirstOrDefault(k => string.Equals(k.Value.Trim(), keyName, StringComparison.OrdinalIgnoreCase));
        var boolElem = new XElement(value ? "true" : "false");
        if (keyElem != null)
        {
            var next = keyElem.ElementsAfterSelf().FirstOrDefault();
            if (next != null)
            {
                next.ReplaceWith(boolElem);
                return;
            }
        }

        dict.Add(new XElement("key", keyName));
        dict.Add(boolElem);
    }

    #endregion
}
