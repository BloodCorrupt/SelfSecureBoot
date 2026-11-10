using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace SelfSecureBoot.Core;

public sealed class PEImage
{
    private byte[] _data;
    public byte[] Data => _data;

    public bool IsPE32Plus { get; }
    public ushort Machine { get; }
    public int ChecksumOffset { get; }
    public int CertDirOffset { get; }
    public int SizeOfHeaders { get; }
    public int SectionsOffset { get; }
    public int NumSections { get; }

    public sealed record Section(string Name, int RawPointer, int RawSize);

    public PEImage(byte[] input)
    {
        if (input == null || input.Length < 0x40 || input[0] != 0x4D || input[1] != 0x5A)
            throw new InvalidDataException("Not an MZ/PE executable file");

        _data = (byte[])input.Clone();

        int peOff = (int)U32(_data, 0x3C);
        if (peOff < 0x40 || peOff + 24 > _data.Length ||
            _data[peOff] != 0x50 || _data[peOff + 1] != 0x45 || _data[peOff + 2] != 0 || _data[peOff + 3] != 0)
        {
            throw new InvalidDataException("Bad PE signature");
        }

        int coff = peOff + 4;
        Machine = U16(_data, coff);
        NumSections = U16(_data, coff + 2);
        int optSize = U16(_data, coff + 16);
        int opt = coff + 20;

        if (optSize < 96 || opt + optSize > _data.Length)
            throw new InvalidDataException("Optional header too small or truncated");

        ushort magic = U16(_data, opt);
        switch (magic)
        {
            case 0x20B:
                IsPE32Plus = true;
                break;
            case 0x10B:
                IsPE32Plus = false;
                break;
            default:
                throw new InvalidDataException($"Unknown optional header magic: 0x{magic:X}");
        }

        ChecksumOffset = opt + 64;
        SizeOfHeaders = (int)U32(_data, opt + 60);

        int dirsOff = opt + (IsPE32Plus ? 112 : 96);
        int nDirs = (int)U32(_data, dirsOff - 4);
        if (nDirs < 5 || dirsOff + nDirs * 8 > opt + optSize)
            throw new InvalidDataException("No Certificate Table entry in PE data directory");

        CertDirOffset = dirsOff + 4 * 8; // Entry 4 is IMAGE_DIRECTORY_ENTRY_SECURITY
        SectionsOffset = opt + optSize;

        if (SectionsOffset + NumSections * 40 > _data.Length ||
            SizeOfHeaders > _data.Length ||
            SizeOfHeaders < SectionsOffset + NumSections * 40)
        {
            throw new InvalidDataException("Section table or headers exceed file bounds");
        }
    }

    public static ushort U16(byte[] d, int o) => (ushort)(d[o] | (d[o + 1] << 8));
    public static uint U32(byte[] d, int o) => (uint)(d[o] | (d[o + 1] << 8) | (d[o + 2] << 16) | (d[o + 3] << 24));

    public void Put32(uint v, int o)
    {
        _data[o] = (byte)(v & 0xFF);
        _data[o + 1] = (byte)((v >> 8) & 0xFF);
        _data[o + 2] = (byte)((v >> 16) & 0xFF);
        _data[o + 3] = (byte)((v >> 24) & 0xFF);
    }

    public (int Offset, int Size) CertTable =>
        ((int)U32(_data, CertDirOffset), (int)U32(_data, CertDirOffset + 4));

    public bool HasCertificateTable => CertTable.Size > 0;

    public List<Section> Sections
    {
        get
        {
            var list = new List<Section>(NumSections);
            for (int i = 0; i < NumSections; i++)
            {
                int o = SectionsOffset + i * 40;
                int nameLen = 0;
                while (nameLen < 8 && _data[o + nameLen] != 0) nameLen++;
                string name = Encoding.UTF8.GetString(_data, o, nameLen);
                int rawPointer = (int)U32(_data, o + 20);
                int rawSize = (int)U32(_data, o + 16);
                list.Add(new Section(name, rawPointer, rawSize));
            }
            return list;
        }
    }

    /// <summary>
    /// Authenticode hash per the PE spec:
    /// Headers up to CheckSum, between CheckSum and CertDir, between CertDir and SizeOfHeaders,
    /// then sections in ascending raw pointer order, then trailing data minus cert table.
    /// </summary>
    public byte[] AuthenticodeHash(HashAlgorithmName algorithm)
    {
        using var hasher = IncrementalHash.CreateHash(algorithm);

        // 1. Hash from start to Checksum
        hasher.AppendData(_data, 0, ChecksumOffset);

        // 2. Hash from Checksum + 4 to CertDirOffset
        hasher.AppendData(_data, ChecksumOffset + 4, CertDirOffset - (ChecksumOffset + 4));

        // 3. Hash from CertDirOffset + 8 to SizeOfHeaders
        hasher.AppendData(_data, CertDirOffset + 8, SizeOfHeaders - (CertDirOffset + 8));

        int hashed = SizeOfHeaders;

        // 4. Hash sections in ascending order of RawPointer
        var sortedSections = Sections.Where(s => s.RawSize > 0)
                                     .OrderBy(s => s.RawPointer)
                                     .ToList();

        foreach (var s in sortedSections)
        {
            int start = Math.Min(s.RawPointer, _data.Length);
            int end = Math.Min(s.RawPointer + s.RawSize, _data.Length);
            if (start < end)
            {
                hasher.AppendData(_data, start, end - start);
            }
            hashed += (end - start);
        }

        // 5. Hash trailing data excluding the Certificate Table
        var (certOff, certSize) = CertTable;
        if (hashed < _data.Length)
        {
            if (certSize > 0 && certOff >= hashed && certOff + certSize <= _data.Length)
            {
                hasher.AppendData(_data, hashed, certOff - hashed);
                if (certOff + certSize < _data.Length)
                {
                    hasher.AppendData(_data, certOff + certSize, _data.Length - (certOff + certSize));
                }
            }
            else
            {
                hasher.AppendData(_data, hashed, _data.Length - hashed);
            }
        }

        return hasher.GetHashAndReset();
    }

    public byte[] Sha256 => AuthenticodeHash(HashAlgorithmName.SHA256);

    /// <summary>
    /// Returns PKCS#7 SignedData blob of the first WIN_CERTIFICATE (type 0x0002) if present.
    /// </summary>
    public byte[]? SignatureBlob
    {
        get
        {
            var (off, size) = CertTable;
            if (size < 8 || off < SizeOfHeaders || off + size > _data.Length)
                return null;

            int dwLength = (int)U32(_data, off);
            ushort type = U16(_data, off + 6);
            if (type != 0x0002 || dwLength < 8 || off + dwLength > _data.Length)
                return null;

            var p7 = new byte[dwLength - 8];
            Buffer.BlockCopy(_data, off + 8, p7, 0, p7.Length);
            return p7;
        }
    }

    public bool StripSignature()
    {
        var (off, size) = CertTable;
        if (size == 0) return false;

        if (off >= SizeOfHeaders && off + size == _data.Length)
        {
            Array.Resize(ref _data, off);
        }

        Put32(0, CertDirOffset);
        Put32(0, CertDirOffset + 4);
        return true;
    }

    public void PadTo8()
    {
        int rem = _data.Length % 8;
        if (rem != 0)
        {
            int pad = 8 - rem;
            Array.Resize(ref _data, _data.Length + pad);
        }
    }

    /// <summary>
    /// Appends WIN_CERTIFICATE { dwLength, wRevision: 0x0200, wCertificateType: 0x0002 } + PKCS#7, 8-byte aligned.
    /// </summary>
    public void AppendCertificate(byte[] pkcs7)
    {
        PadTo8();
        int off = _data.Length;

        // WIN_CERTIFICATE: 4 bytes length, 2 bytes wRevision (0x0200), 2 bytes wCertificateType (0x0002)
        int bodySize = 8 + pkcs7.Length;
        int rem = bodySize % 8;
        int paddedSize = rem == 0 ? bodySize : bodySize + (8 - rem);

        var body = new byte[paddedSize];
        uint lenU32 = (uint)paddedSize;
        body[0] = (byte)(lenU32 & 0xFF);
        body[1] = (byte)((lenU32 >> 8) & 0xFF);
        body[2] = (byte)((lenU32 >> 16) & 0xFF);
        body[3] = (byte)((lenU32 >> 24) & 0xFF);

        body[4] = 0x00; // wRevision = 0x0200
        body[5] = 0x02;
        body[6] = 0x02; // wCertificateType = 0x0002 (WIN_CERT_TYPE_PKCS_SIGNED_DATA)
        body[7] = 0x00;

        Buffer.BlockCopy(pkcs7, 0, body, 8, pkcs7.Length);

        // Append to data
        int oldLen = _data.Length;
        Array.Resize(ref _data, oldLen + body.Length);
        Buffer.BlockCopy(body, 0, _data, oldLen, body.Length);

        // Update Security Directory in PE optional header
        Put32((uint)off, CertDirOffset);
        Put32(lenU32, CertDirOffset + 4);
    }

    /// <summary>
    /// Recomputes PE optional header CheckSum using standard 16-bit fold algorithm.
    /// </summary>
    public void UpdateChecksum()
    {
        Put32(0, ChecksumOffset);
        int n = _data.Length;
        ulong sum = 0;

        for (int i = 0; i + 1 < n; i += 2)
        {
            sum += (uint)(_data[i] | (_data[i + 1] << 8));
            sum = (sum & 0xFFFF) + (sum >> 16);
        }

        if ((n & 1) != 0)
        {
            sum += _data[n - 1];
            sum = (sum & 0xFFFF) + (sum >> 16);
        }

        sum = (sum & 0xFFFF) + (sum >> 16);
        sum = (sum & 0xFFFF) + (sum >> 16);

        uint finalChecksum = (uint)((sum & 0xFFFF) + (ulong)n);
        Put32(finalChecksum, ChecksumOffset);
    }
}

