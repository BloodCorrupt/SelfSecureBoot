using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace SelfSecureBoot.Core;

public sealed class SigningIdentity : IDisposable
{
    public RSA PrivateKey { get; }
    public byte[] CertificateDER { get; }
    public X509Certificate2 Certificate { get; }

    public SigningIdentity(byte[] keyFileBytes, byte[] certFileBytes)
    {
        string keyText = Encoding.UTF8.GetString(keyFileBytes);
        var rsa = RSA.Create();

        byte[]? pkcs1 = PemHelper.GetBody(keyText, "RSA PRIVATE KEY");
        if (pkcs1 != null)
        {
            rsa.ImportRSAPrivateKey(pkcs1, out _);
        }
        else
        {
            byte[]? pkcs8 = PemHelper.GetBody(keyText, "PRIVATE KEY");
            if (pkcs8 != null)
            {
                rsa.ImportPkcs8PrivateKey(pkcs8, out _);
            }
            else if (keyText.Contains("EC PRIVATE KEY"))
            {
                throw new NotSupportedException("EC keys are not supported for UEFI Secure Boot; use an RSA key.");
            }
            else
            {
                // Try importing directly as PEM
                try
                {
                    rsa.ImportFromPem(keyText);
                }
                catch (Exception ex)
                {
                    throw new FormatException($"Unrecognized or invalid private key file: {ex.Message}");
                }
            }
        }

        PrivateKey = rsa;
        CertificateDER = ExtractCertificateDer(certFileBytes);
        Certificate = X509CertificateLoader.LoadCertificate(CertificateDER);
    }

    public SigningIdentity(RSA rsa, byte[] certDer)
    {
        PrivateKey = rsa;
        CertificateDER = certDer;
        Certificate = X509CertificateLoader.LoadCertificate(certDer);
    }

    public static byte[] ExtractCertificateDer(byte[] fileBytes)
    {
        if (fileBytes.Length > 0 && fileBytes[0] == 0x30)
        {
            return fileBytes; // Already raw DER
        }

        string text = Encoding.UTF8.GetString(fileBytes);
        byte[]? der = PemHelper.GetBody(text, "CERTIFICATE");
        if (der == null)
            throw new FormatException("Unrecognized certificate file (expected PEM or DER)");

        return der;
    }

    public static SigningIdentity Load(string keyPath, string certPath)
    {
        return new SigningIdentity(File.ReadAllBytes(keyPath), File.ReadAllBytes(certPath));
    }

    public string SubjectSummary
    {
        get
        {
            try
            {
                return Certificate.GetNameInfo(X509NameType.SimpleName, false) ?? Certificate.Subject;
            }
            catch
            {
                return Certificate.Subject;
            }
        }
    }

    public byte[] Sign(byte[] data)
    {
        return PrivateKey.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
    }

    public void Dispose()
    {
        PrivateKey.Dispose();
        Certificate.Dispose();
    }
}

public static class Authenticode
{
    /// <summary>
    /// Builds the PKCS#7 SignedData (wrapped in ContentInfo) that Authenticode expects.
    /// </summary>
    public static byte[] BuildPKCS7(byte[] imageHash, SigningIdentity identity)
    {
        var algSha256 = DerHelper.Sequence(DerHelper.Oid(OID.Sha256), DerHelper.Null);

        // SpcIndirectDataContent { data { SPC_PE_IMAGE_DATA, SpcPeImageData }, messageDigest DigestInfo }
        byte[] obsolete = Encoding.BigEndianUnicode.GetBytes("<<<Obsolete>>>");
        byte[] spcPeImageData = DerHelper.Sequence(
            [0x03, 0x01, 0x00], // flags BIT STRING (empty)
            DerHelper.Explicit(0, DerHelper.Explicit(2, DerHelper.ImplicitPrimitive(0, obsolete))) // file -> SpcLink.file -> unicode
        );

        byte[] spcIndirect = DerHelper.Sequence(
            DerHelper.Sequence(DerHelper.Oid(OID.SpcPEImageData), spcPeImageData),
            DerHelper.Sequence(algSha256, DerHelper.Octets(imageHash)) // DigestInfo (digest must be last)
        );

        // Authenticode quirk: messageDigest covers SpcIndirectDataContent body without the outer SEQUENCE header
        var spcTlv = DerHelper.Read(spcIndirect, 0);
        byte[] spcBody = DerHelper.Content(spcIndirect, spcTlv);
        byte[] messageDigest = SHA256.HashData(spcBody);

        var attrContentType = DerHelper.Sequence(
            DerHelper.Oid(OID.ContentType),
            DerHelper.Set(DerHelper.Oid(OID.SpcIndirectData))
        );
        var attrMessageDigest = DerHelper.Sequence(
            DerHelper.Oid(OID.MessageDigest),
            DerHelper.Set(DerHelper.Octets(messageDigest))
        );

        // Authenticated attributes SET OF sorted lexicographically
        var sortedAttrsList = new List<byte[]> { attrContentType, attrMessageDigest }
            .OrderBy(x => x, new DerHelper.ByteArrayComparer())
            .ToList();

        byte[] attrsBody = DerHelper.Concat(sortedAttrsList);
        byte[] setDer = DerHelper.TLVEncode(0x31, attrsBody);

        // Sign the SET OF DER bytes with RSA SHA-256 PKCS#1 v1.5
        byte[] signature = identity.Sign(setDer);

        var (issuer, serial) = ExtractIssuerAndSerial(identity.CertificateDER);

        byte[] signerInfo = DerHelper.Sequence(
            DerHelper.Integer(1),
            DerHelper.Sequence(issuer, serial),
            algSha256,
            DerHelper.TLVEncode(0xA0, attrsBody), // Signed attributes under [0] tag (0xA0)
            DerHelper.Sequence(DerHelper.Oid(OID.Rsa), DerHelper.Null),
            DerHelper.Octets(signature)
        );

        byte[] signedData = DerHelper.Sequence(
            DerHelper.Integer(1),
            DerHelper.Set(algSha256),
            DerHelper.Sequence(DerHelper.Oid(OID.SpcIndirectData), DerHelper.Explicit(0, spcIndirect)), // PKCS#7 v1.5: bare SEQUENCE
            DerHelper.TLVEncode(0xA0, identity.CertificateDER), // [0] IMPLICIT certificates
            DerHelper.Set(signerInfo)
        );

        return DerHelper.Sequence(
            DerHelper.Oid(OID.SignedData),
            DerHelper.Explicit(0, signedData)
        );
    }

    public static (byte[] Issuer, byte[] Serial) ExtractIssuerAndSerial(byte[] certDer)
    {
        var outer = DerHelper.Read(certDer, 0);
        var outerKids = DerHelper.Children(certDer, outer);
        if (outerKids.Count == 0) throw new FormatException("Malformed certificate");

        var tbs = outerKids[0];
        var kids = DerHelper.Children(certDer, tbs);
        if (kids.Count > 0 && kids[0].Tag == 0xA0)
        {
            kids.RemoveAt(0); // Version tag
        }

        if (kids.Count < 4 || kids[0].Tag != 0x02 || kids[2].Tag != 0x30)
            throw new FormatException("Malformed certificate TBS fields");

        byte[] serial = DerHelper.Full(certDer, kids[0]);
        byte[] issuer = DerHelper.Full(certDer, kids[2]);
        return (issuer, serial);
    }

    /// <summary>
    /// Signs an image in memory: strips any old signature, pads to 8, computes Authenticode hash,
    /// builds and appends PKCS#7 Authenticode signature, and updates the PE checksum.
    /// </summary>
    public static (byte[] SignedData, byte[] Hash) Sign(byte[] input, SigningIdentity identity)
    {
        var pe = new PEImage(input);
        pe.StripSignature();
        pe.PadTo8();
        byte[] hash = pe.Sha256;
        byte[] p7 = BuildPKCS7(hash, identity);
        pe.AppendCertificate(p7);
        pe.UpdateChecksum();
        return (pe.Data, hash);
    }

    /// <summary>
    /// Constructs an EFI_SIGNATURE_LIST binary holding one X.509 certificate for UEFI BIOS enrollment.
    /// </summary>
    public static byte[] MakeESL(byte[] certificateDER)
    {
        // EFI_CERT_X509_GUID: a5c059a1-94e4-4aa7-87b5-ab155c2bf072 (mixed-endian on disk)
        byte[] guidBytes = [0xa1, 0x59, 0xc0, 0xa5, 0xe4, 0x94, 0xa7, 0x4a, 0x87, 0xb5, 0xab, 0x15, 0x5c, 0x2b, 0xf0, 0x72];

        uint sigSize = (uint)(16 + certificateDER.Length);
        uint listSize = 28 + sigSize;

        byte[] esl = new byte[listSize];
        Buffer.BlockCopy(guidBytes, 0, esl, 0, 16);

        // uint32 listSize
        esl[16] = (byte)(listSize & 0xFF);
        esl[17] = (byte)((listSize >> 8) & 0xFF);
        esl[18] = (byte)((listSize >> 16) & 0xFF);
        esl[19] = (byte)((listSize >> 24) & 0xFF);

        // uint32 headerSize = 0
        esl[20] = 0;
        esl[21] = 0;
        esl[22] = 0;
        esl[23] = 0;

        // uint32 sigSize
        esl[24] = (byte)(sigSize & 0xFF);
        esl[25] = (byte)((sigSize >> 8) & 0xFF);
        esl[26] = (byte)((sigSize >> 16) & 0xFF);
        esl[27] = (byte)((sigSize >> 24) & 0xFF);

        // 16-byte random SignatureOwner GUID (UUID v4)
        byte[] owner = new byte[16];
        Random.Shared.NextBytes(owner);
        owner[6] = (byte)((owner[6] & 0x0F) | 0x40);
        owner[8] = (byte)((owner[8] & 0x3F) | 0x80);
        Buffer.BlockCopy(owner, 0, esl, 28, 16);

        // Append certificate DER
        Buffer.BlockCopy(certificateDER, 0, esl, 44, certificateDER.Length);

        return esl;
    }
}
