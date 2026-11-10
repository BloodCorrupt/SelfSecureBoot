using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace SelfSecureBoot.Core;

public sealed class SignatureInfo
{
    public string SignerName { get; set; } = "unknown signer";
    public string IssuerName { get; set; } = "";
    public DateTime? NotAfter { get; set; }
    public string DigestAlgorithm { get; set; } = "?";
    public byte[] DigestInSignature { get; set; } = [];
    public byte[] ComputedDigest { get; set; } = [];
    public bool DigestMatches { get; set; }
    public bool SignatureValid { get; set; }
    public byte[]? SignerCertificateDER { get; set; }
    public List<string> Problems { get; } = new();

    public bool IsValid => DigestMatches && SignatureValid;
}

public abstract record FileStatus
{
    public sealed record NotPEStatus(string Reason) : FileStatus;
    public sealed record UnsignedStatus : FileStatus;
    public sealed record SignedStatus(SignatureInfo Info) : FileStatus;
    public sealed record AppleFormatStatus : FileStatus;

    public static FileStatus NotPE(string reason) => new NotPEStatus(reason);
    public static FileStatus Unsigned() => new UnsignedStatus();
    public static FileStatus Signed(SignatureInfo info) => new SignedStatus(info);
    public static FileStatus AppleFormat() => new AppleFormatStatus();
}

public static class Inspector
{
    public static FileStatus Inspect(string path)
    {
        try
        {
            byte[] data = File.ReadAllBytes(path);
            return Inspect(data);
        }
        catch (Exception ex)
        {
            return FileStatus.NotPE($"Unreadable: {ex.Message}");
        }
    }

    public static FileStatus Inspect(byte[] data)
    {
        PEImage pe;
        try
        {
            pe = new PEImage(data);
        }
        catch (Exception ex)
        {
            return FileStatus.NotPE(ex.Message);
        }

        if (!pe.HasCertificateTable)
            return FileStatus.Unsigned();

        byte[]? p7 = pe.SignatureBlob;
        if (p7 == null)
            return FileStatus.AppleFormat();

        return FileStatus.Signed(ParsePKCS7(p7, pe));
    }

    public static byte[]? ComputeImageHash(string alg, PEImage pe)
    {
        return alg.ToLowerInvariant() switch
        {
            "sha256" => pe.AuthenticodeHash(HashAlgorithmName.SHA256),
            "sha1" => pe.AuthenticodeHash(HashAlgorithmName.SHA1),
            "sha384" => pe.AuthenticodeHash(HashAlgorithmName.SHA384),
            "sha512" => pe.AuthenticodeHash(HashAlgorithmName.SHA512),
            _ => null
        };
    }

    public static byte[]? Hash(string alg, byte[] data)
    {
        return alg.ToLowerInvariant() switch
        {
            "sha256" => SHA256.HashData(data),
            "sha1" => SHA1.HashData(data),
            "sha384" => SHA384.HashData(data),
            "sha512" => SHA512.HashData(data),
            _ => null
        };
    }

    public static string AlgName(string oid)
    {
        return oid switch
        {
            OID.Sha1 => "sha1",
            OID.Sha256 => "sha256",
            OID.Sha384 => "sha384",
            OID.Sha512 => "sha512",
            _ => oid
        };
    }

    public static HashAlgorithmName? ToHashAlgorithmName(string alg)
    {
        return alg.ToLowerInvariant() switch
        {
            "sha1" => HashAlgorithmName.SHA1,
            "sha256" => HashAlgorithmName.SHA256,
            "sha384" => HashAlgorithmName.SHA384,
            "sha512" => HashAlgorithmName.SHA512,
            _ => null
        };
    }

    public static SignatureInfo ParsePKCS7(byte[] p7, PEImage pe)
    {
        var info = new SignatureInfo();
        try
        {
            // ContentInfo { signedData OID, [0] SignedData }
            var ci = DerHelper.Read(p7, 0);
            var ciKids = DerHelper.Children(p7, ci);
            if (ciKids.Count < 2 || ciKids[0].Tag != 0x06 || DerHelper.OidString(DerHelper.Content(p7, ciKids[0])) != OID.SignedData)
                throw new FormatException("Not PKCS#7 SignedData");

            var sd = DerHelper.Children(p7, ciKids[1])[0];
            var sdKids = DerHelper.Children(p7, sd);
            if (sdKids.Count < 4) throw new FormatException("Malformed SignedData fields");

            // encapContentInfo { spcIndirectData OID, [0] SpcIndirectDataContent }
            var eci = sdKids[2];
            var eciKids = DerHelper.Children(p7, eci);
            if (eciKids.Count < 2 || DerHelper.OidString(DerHelper.Content(p7, eciKids[0])) != OID.SpcIndirectData)
                throw new FormatException("Missing SpcIndirectDataContent in encapContentInfo");

            var spc = DerHelper.Children(p7, eciKids[1])[0];
            var spcKids = DerHelper.Children(p7, spc);
            if (spcKids.Count == 0) throw new FormatException("Missing DigestInfo in SpcIndirectDataContent");

            var digestInfo = spcKids[^1];
            var digestInfoKids = DerHelper.Children(p7, digestInfo);
            if (digestInfoKids.Count != 2) throw new FormatException("Malformed DigestInfo");

            var algOidKids = DerHelper.Children(p7, digestInfoKids[0]);
            if (algOidKids.Count == 0) throw new FormatException("Missing AlgorithmIdentifier");

            info.DigestAlgorithm = AlgName(DerHelper.OidString(DerHelper.Content(p7, algOidKids[0])));
            info.DigestInSignature = DerHelper.Content(p7, digestInfoKids[1]);

            byte[]? computed = ComputeImageHash(info.DigestAlgorithm, pe);
            if (computed != null)
            {
                info.ComputedDigest = computed;
                info.DigestMatches = computed.AsSpan().SequenceEqual(info.DigestInSignature);
                if (!info.DigestMatches)
                {
                    info.Problems.Add("Image hash does not match signed digest (file was modified after signing)");
                }
            }
            else
            {
                info.Problems.Add($"Unsupported digest algorithm: {info.DigestAlgorithm}");
            }

            // Extract certificates [0] IMPLICIT and signerInfos SET
            var certs = new List<byte[]>();
            DerHelper.TLV? signerInfosTlv = null;

            for (int i = 3; i < sdKids.Count; i++)
            {
                var k = sdKids[i];
                if (k.Tag == 0xA0)
                {
                    foreach (var c in DerHelper.Children(p7, k))
                    {
                        certs.Add(DerHelper.Full(p7, c));
                    }
                }
                else if (k.Tag == 0x31)
                {
                    signerInfosTlv = k;
                }
            }

            if (signerInfosTlv == null) throw new FormatException("Missing SignerInfos SET");
            var signerKids = DerHelper.Children(p7, signerInfosTlv);
            if (signerKids.Count == 0) throw new FormatException("Empty SignerInfos");

            var si = signerKids[0];
            var siKids = DerHelper.Children(p7, si);
            if (siKids.Count < 6) throw new FormatException("Truncated SignerInfo fields");

            int idx = 3;
            if (siKids[idx].Tag != 0xA0) throw new FormatException("No signed attributes in SignerInfo");
            var signedAttrs = siKids[idx];
            idx++;

            var sigAlgKids = DerHelper.Children(p7, siKids[idx]);
            string sigAlgOid = sigAlgKids.Count > 0 ? DerHelper.OidString(DerHelper.Content(p7, sigAlgKids[0])) : "";
            idx++;

            byte[] signature = DerHelper.Content(p7, siKids[idx]);

            // messageDigest attribute must equal hash(SpcIndirectDataContent body)
            byte[]? messageDigestAttr = null;
            foreach (var attr in DerHelper.Children(p7, signedAttrs))
            {
                var ak = DerHelper.Children(p7, attr);
                if (ak.Count == 2 && ak[0].Tag == 0x06)
                {
                    if (DerHelper.OidString(DerHelper.Content(p7, ak[0])) == OID.MessageDigest)
                    {
                        var values = DerHelper.Children(p7, ak[1]);
                        if (values.Count > 0)
                        {
                            messageDigestAttr = DerHelper.Content(p7, values[0]);
                        }
                    }
                }
            }

            byte[]? expectedMd = Hash(info.DigestAlgorithm, DerHelper.Content(p7, spc));
            if (messageDigestAttr == null)
            {
                info.Problems.Add("Missing messageDigest attribute");
            }
            else if (expectedMd == null || !expectedMd.AsSpan().SequenceEqual(messageDigestAttr))
            {
                info.Problems.Add("messageDigest attribute does not cover SpcIndirectDataContent");
            }

            // Verify RSA signature over SET OF [0x31] signed attributes
            byte[] setData = DerHelper.TLVEncode(0x31, DerHelper.Content(p7, signedAttrs));
            bool rsaOk = sigAlgOid == OID.Rsa || sigAlgOid.StartsWith("1.2.840.113549.1.1.");
            if (!rsaOk)
            {
                info.Problems.Add($"Unsupported signature algorithm: {sigAlgOid}");
            }

            var hashAlgName = ToHashAlgorithmName(info.DigestAlgorithm);
            if (rsaOk && hashAlgName.HasValue && expectedMd != null && expectedMd.AsSpan().SequenceEqual(messageDigestAttr ?? []))
            {
                foreach (var certDer in certs)
                {
                    try
                    {
                        using var cert = X509CertificateLoader.LoadCertificate(certDer);
                        using var rsa = cert.GetRSAPublicKey();
                        if (rsa != null && rsa.VerifyData(setData, signature, hashAlgName.Value, RSASignaturePadding.Pkcs1))
                        {
                            info.SignatureValid = true;
                            info.SignerCertificateDER = certDer;
                            info.SignerName = cert.GetNameInfo(X509NameType.SimpleName, false) ?? cert.Subject;
                            info.IssuerName = cert.GetNameInfo(X509NameType.SimpleName, true) ?? cert.Issuer;
                            info.NotAfter = cert.NotAfter;
                            break;
                        }
                    }
                    catch
                    {
                        // Try next cert
                    }
                }

                if (!info.SignatureValid)
                {
                    info.Problems.Add("RSA signature failed to verify against embedded certificate(s)");
                }
            }

            if (!info.SignatureValid && certs.Count > 0)
            {
                try
                {
                    using var firstCert = X509CertificateLoader.LoadCertificate(certs[0]);
                    info.SignerName = firstCert.GetNameInfo(X509NameType.SimpleName, false) ?? firstCert.Subject;
                }
                catch { }
            }
        }
        catch (Exception ex)
        {
            info.Problems.Add(ex.Message);
        }

        return info;
    }

    public static string SubjectCommonName(byte[] certDer)
    {
        try
        {
            using var cert = X509CertificateLoader.LoadCertificate(certDer);
            return cert.GetNameInfo(X509NameType.SimpleName, false) ?? cert.Subject;
        }
        catch
        {
            return "certificate";
        }
    }

    public static DateTime? NotAfter(byte[] certDer)
    {
        try
        {
            using var cert = X509CertificateLoader.LoadCertificate(certDer);
            return cert.NotAfter;
        }
        catch
        {
            return null;
        }
    }
}
