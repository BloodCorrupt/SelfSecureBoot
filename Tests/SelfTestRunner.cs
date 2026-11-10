using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using SelfSecureBoot.Core;

namespace SelfSecureBoot.Tests;

public static class SelfTestRunner
{
    public static bool RunTests()
    {
        Console.WriteLine("=================================================");
        Console.WriteLine("  SelfSecureBoot / EFI Signer - Test Suite");
        Console.WriteLine("=================================================");

        int passed = 0;
        int failed = 0;

        void Assert(string testName, bool condition, string detail = "")
        {
            if (condition)
            {
                Console.ForegroundColor = ConsoleColor.Green;
                Console.Write("[PASS] ");
                Console.ResetColor();
                Console.WriteLine(testName);
                passed++;
            }
            else
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.Write("[FAIL] ");
                Console.ResetColor();
                Console.WriteLine($"{testName} - {detail}");
                failed++;
            }
        }

        string tempDir = Path.Combine(Path.GetTempPath(), "SelfSecureBootTest_" + Guid.NewGuid().ToString("N")[..8]);
        Directory.CreateDirectory(tempDir);

        try
        {
            // Test 1: ASN.1 DER OID and Length
            try
            {
                byte[] len1 = DerHelper.EncodeLength(10);
                byte[] len2 = DerHelper.EncodeLength(300);
                byte[] oidSha256 = DerHelper.Oid(OID.Sha256);
                string oidStr = DerHelper.OidString(DerHelper.Content(oidSha256, DerHelper.Read(oidSha256, 0)));

                Assert("DER Helper: OID & Length encoding",
                    len1.Length == 1 && len1[0] == 10 &&
                    len2.Length == 3 && len2[0] == 0x82 &&
                    oidStr == OID.Sha256);
            }
            catch (Exception ex)
            {
                Assert("DER Helper: OID & Length encoding", false, ex.Message);
            }

            // Test 2: KeyStore Generation & Certificate Export
            KeyStore keyStore = new KeyStore(tempDir);
            try
            {
                keyStore.Generate("Test SecureBoot CA", days: 365, keySize: 2048);
                bool exists = keyStore.Exists;
                var info = keyStore.GetCertificateInfo();
                byte[]? der = keyStore.CertificateDER;

                Assert("KeyStore: RSA 2048 Generation & Info",
                    exists && info != null && info.Subject.Contains("Test SecureBoot CA") && der != null && der.Length > 0);

                // Test ESL Generation
                byte[] esl = File.ReadAllBytes(keyStore.EslPath);
                Assert("KeyStore: EFI Signature List (ESL) creation",
                    esl.Length > 44 && esl[0] == 0xa1 && esl[1] == 0x59);
            }
            catch (Exception ex)
            {
                Assert("KeyStore: RSA Generation & ESL", false, ex.Message);
            }

            // Test 3: PE Image Parsing & Authenticode Inspection of Windows bootmgfw.efi
            string winBootEfi = @"C:\Windows\Boot\EFI\bootmgfw.efi";
            if (File.Exists(winBootEfi))
            {
                try
                {
                    byte[] winBytes = File.ReadAllBytes(winBootEfi);
                    var pe = new PEImage(winBytes);
                    byte[] hash = pe.Sha256;

                    Assert("PEImage: Parse 64-bit EFI executable (bootmgfw.efi)",
                        pe.IsPE32Plus && pe.Sections.Count > 0 && hash.Length == 32);

                    var inspect = Inspector.Inspect(winBytes);
                    bool isMsSigned = false;
                    if (inspect is FileStatus.SignedStatus signed)
                    {
                        isMsSigned = signed.Info.IsValid &&
                                     (signed.Info.SignerName.Contains("Microsoft", StringComparison.OrdinalIgnoreCase) ||
                                      signed.Info.IssuerName.Contains("Microsoft", StringComparison.OrdinalIgnoreCase));
                    }

                    Assert("Inspector: Authenticode signature validation on Microsoft EFI",
                        isMsSigned, "Signature on bootmgfw.efi failed verification");
                }
                catch (Exception ex)
                {
                    Assert("PEImage & Inspector on Windows bootmgfw.efi", false, ex.Message);
                }

                // Test 4: Signing a PE file in place & Self-check verification
                try
                {
                    string testEfiPath = Path.Combine(tempDir, "test_boot.efi");
                    File.Copy(winBootEfi, testEfiPath, overwrite: true);

                    using var identity = keyStore.Identity();

                    var entry = new EFIFileEntry
                    {
                        FullPath = testEfiPath,
                        RelativePath = "EFI/OC/test_boot.efi",
                        Size = new FileInfo(testEfiPath).Length,
                        Status = Inspector.Inspect(testEfiPath),
                        Role = FileRole.OpenCore,
                        Verdict = Verdict.NeedsSignature
                    };

                    string backupDir = Path.Combine(tempDir, "Backups");
                    var signOutcome = SignerService.Sign(entry, identity, backupDir);

                    Assert("SignerService: In-memory sign & self-check",
                        signOutcome.Error == null && signOutcome.Hash != null);

                    // Re-inspect signed file
                    var reInspect = Inspector.Inspect(testEfiPath);
                    bool signedByUs = false;
                    if (reInspect is FileStatus.SignedStatus signedStatus)
                    {
                        signedByUs = signedStatus.Info.IsValid &&
                                     signedStatus.Info.SignerCertificateDER != null &&
                                     signedStatus.Info.SignerCertificateDER.AsSpan().SequenceEqual(identity.CertificateDER);
                    }

                    Assert("SignerService: Verified file signed with custom certificate",
                        signedByUs, "Expected signature to match our generated certificate");

                    // Test 5: Restore / Revert from backup
                    var revertOutcome = RestoreService.Revert(entry, [backupDir]);
                    Assert("RestoreService: Revert file to original backup",
                        revertOutcome.Error == null && revertOutcome.Method != null);

                    var revertedInspect = Inspector.Inspect(testEfiPath);
                    bool revertedToMs = false;
                    if (revertedInspect is FileStatus.SignedStatus origSigned)
                    {
                        revertedToMs = origSigned.Info.IsValid &&
                                       origSigned.Info.SignerName.Contains("Microsoft", StringComparison.OrdinalIgnoreCase);
                    }

                    Assert("RestoreService: Original Microsoft signature intact after revert",
                        revertedToMs);
                }
                catch (Exception ex)
                {
                    Assert("SignerService & RestoreService tests", false, ex.Message);
                }
            }
            else
            {
                Console.WriteLine("[INFO] C:\\Windows\\Boot\\EFI\\bootmgfw.efi not found, skipping real binary test.");
            }

            // Test 6: OpenCore config.plist Warnings and Fixes
            try
            {
                string ocDir = Path.Combine(tempDir, "EFI", "OC");
                Directory.CreateDirectory(ocDir);
                string plistPath = Path.Combine(ocDir, "config.plist");

                string samplePlist = """
                <?xml version="1.0" encoding="UTF-8"?>
                <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
                <plist version="1.0">
                <dict>
                    <key>Misc</key>
                    <dict>
                        <key>Security</key>
                        <dict>
                            <key>SecureBootModel</key>
                            <string>Disabled</string>
                            <key>Vault</key>
                            <string>Optional</string>
                        </dict>
                        <key>Tools</key>
                        <array>
                            <dict>
                                <key>Path</key>
                                <string>OpenShell.efi</string>
                                <key>Enabled</key>
                                <true/>
                            </dict>
                        </array>
                    </dict>
                    <key>UEFI</key>
                    <dict>
                        <key>Quirks</key>
                        <dict>
                            <key>DisableSecurityPolicy</key>
                            <true/>
                        </dict>
                        <key>Drivers</key>
                        <array>
                            <dict>
                                <key>Path</key>
                                <string>OpenRuntime.efi</string>
                                <key>Enabled</key>
                                <true/>
                            </dict>
                        </array>
                    </dict>
                </dict>
                </plist>
                """;

                File.WriteAllText(plistPath, samplePlist);

                var ocConfig = OpenCoreConfig.Load(tempDir);
                Assert("OpenCoreConfig: Detect SecureBootModel=Disabled & Warnings",
                    ocConfig != null &&
                    ocConfig.Warnings.Count == 3 &&
                    ocConfig.SecureBootModel == "Disabled" &&
                    ocConfig.DisableSecurityPolicy == true &&
                    ocConfig.EnabledTools.Contains("OpenShell.efi"));

                // Apply Fix 1: SecureBootModel to Default
                OpenCoreConfig.ApplyFix(ConfigFix.SecureBootModelDefault, tempDir, Path.Combine(tempDir, "Backups"));
                var ocAfter1 = OpenCoreConfig.Load(tempDir);
                Assert("OpenCoreConfig: Fix SecureBootModel -> Default",
                    ocAfter1?.SecureBootModel == "Default");

                // Apply Fix 2: DisableSecurityPolicy to false
                OpenCoreConfig.ApplyFix(ConfigFix.DisableSecurityPolicyOff, tempDir, Path.Combine(tempDir, "Backups"));
                var ocAfter2 = OpenCoreConfig.Load(tempDir);
                Assert("OpenCoreConfig: Fix DisableSecurityPolicy -> false",
                    ocAfter2?.DisableSecurityPolicy == false);

                // Apply Fix 3: Disable OpenShell.efi
                OpenCoreConfig.ApplyFix(ConfigFix.DisableTool("OpenShell.efi"), tempDir, Path.Combine(tempDir, "Backups"));
                var ocAfter3 = OpenCoreConfig.Load(tempDir);
                Assert("OpenCoreConfig: Fix Disable OpenShell.efi",
                    ocAfter3 != null && !ocAfter3.EnabledTools.Contains("OpenShell.efi"));

                // Test Restore Config
                string restoredBak = RestoreService.RestoreConfig(tempDir, [Path.Combine(tempDir, "Backups")]);
                var ocRestored = OpenCoreConfig.Load(tempDir);
                Assert("RestoreService: Restore original config.plist",
                    ocRestored?.SecureBootModel == "Disabled" && !string.IsNullOrEmpty(restoredBak));
            }
            catch (Exception ex)
            {
                Assert("OpenCoreConfig XML & Fix tests", false, ex.Message);
            }
        }
        finally
        {
            try { Directory.Delete(tempDir, true); } catch { }
        }

        Console.WriteLine();
        Console.WriteLine($"Test Results: {passed} passed, {failed} failed.");
        Console.WriteLine("=================================================");
        return failed == 0;
    }
}

