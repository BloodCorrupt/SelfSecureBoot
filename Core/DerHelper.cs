using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace SelfSecureBoot.Core;

public static class OID
{
    public const string Sha1 = "1.3.14.3.2.26";
    public const string Sha256 = "2.16.840.1.101.3.4.2.1";
    public const string Sha384 = "2.16.840.1.101.3.4.2.2";
    public const string Sha512 = "2.16.840.1.101.3.4.2.3";
    public const string Rsa = "1.2.840.113549.1.1.1";
    public const string SignedData = "1.2.840.113549.1.7.2";
    public const string ContentType = "1.2.840.113549.1.9.3";
    public const string MessageDigest = "1.2.840.113549.1.9.4";
    public const string SpcIndirectData = "1.3.6.1.4.1.311.2.1.4";
    public const string SpcPEImageData = "1.3.6.1.4.1.311.2.1.15";
    public const string CommonName = "2.5.4.3";
}

/// <summary>
/// Minimal, high-performance DER encoder/decoder for Authenticode PKCS#7 and X.509 certificates.
/// </summary>
public static class DerHelper
{
    public sealed record TLV(byte Tag, int HeaderLength, int Length, int Offset)
    {
        public int ContentOffset => Offset + HeaderLength;
        public int End => Offset + HeaderLength + Length;
        public int TotalLength => HeaderLength + Length;
    }

    public static byte[] EncodeLength(int n)
    {
        if (n < 0x80)
        {
            return [(byte)n];
        }

        var bytes = new List<byte>();
        int v = n;
        while (v > 0)
        {
            bytes.Insert(0, (byte)(v & 0xFF));
            v >>= 8;
        }

        var result = new byte[1 + bytes.Count];
        result[0] = (byte)(0x80 | bytes.Count);
        bytes.CopyTo(result, 1);
        return result;
    }

    public static byte[] TLVEncode(byte tag, byte[] content)
    {
        var lenBytes = EncodeLength(content.Length);
        var result = new byte[1 + lenBytes.Length + content.Length];
        result[0] = tag;
        Buffer.BlockCopy(lenBytes, 0, result, 1, lenBytes.Length);
        Buffer.BlockCopy(content, 0, result, 1 + lenBytes.Length, content.Length);
        return result;
    }

    public static byte[] Concat(IEnumerable<byte[]> items)
    {
        int total = items.Sum(i => i.Length);
        var res = new byte[total];
        int pos = 0;
        foreach (var it in items)
        {
            Buffer.BlockCopy(it, 0, res, pos, it.Length);
            pos += it.Length;
        }
        return res;
    }

    public static byte[] Sequence(params byte[][] items)
    {
        return TLVEncode(0x30, Concat(items));
    }

    public static byte[] Sequence(IEnumerable<byte[]> items)
    {
        return TLVEncode(0x30, Concat(items));
    }

    public static byte[] Set(params byte[][] items)
    {
        return Set((IEnumerable<byte[]>)items);
    }

    public static byte[] Set(IEnumerable<byte[]> items)
    {
        // DER rules require elements in a SET to be sorted lexicographically
        var sorted = items.OrderBy(x => x, new ByteArrayComparer()).ToList();
        return TLVEncode(0x31, Concat(sorted));
    }

    public static byte[] Octets(byte[] d) => TLVEncode(0x04, d);

    public static readonly byte[] Null = [0x05, 0x00];

    public static byte[] Integer(long n)
    {
        if (n == 0) return [0x02, 0x01, 0x00];

        var bytes = new List<byte>();
        long v = n;
        while (v > 0)
        {
            bytes.Insert(0, (byte)(v & 0xFF));
            v >>= 8;
        }

        if ((bytes[0] & 0x80) != 0)
        {
            bytes.Insert(0, 0x00);
        }

        return TLVEncode(0x02, bytes.ToArray());
    }

    public static byte[] Explicit(byte n, byte[] content) => TLVEncode((byte)(0xA0 | n), content);

    public static byte[] ImplicitPrimitive(byte n, byte[] content) => TLVEncode((byte)(0x80 | n), content);

    public static byte[] Oid(string s)
    {
        var parts = s.Split('.').Select(int.Parse).ToArray();
        var body = new List<byte> { (byte)(40 * parts[0] + parts[1]) };
        for (int i = 2; i < parts.Length; i++)
        {
            int p = parts[i];
            var enc = new List<byte> { (byte)(p & 0x7F) };
            int v = p >> 7;
            while (v > 0)
            {
                enc.Insert(0, (byte)(0x80 | (v & 0x7F)));
                v >>= 7;
            }
            body.AddRange(enc);
        }
        return TLVEncode(0x06, body.ToArray());
    }

    public static string OidString(byte[] content)
    {
        if (content == null || content.Length == 0) return "";
        var parts = new List<string>
        {
            (content[0] / 40).ToString(),
            (content[0] % 40).ToString()
        };

        int v = 0;
        for (int i = 1; i < content.Length; i++)
        {
            byte x = content[i];
            v = (v << 7) | (x & 0x7F);
            if ((x & 0x80) == 0)
            {
                parts.Add(v.ToString());
                v = 0;
            }
        }
        return string.Join(".", parts);
    }

    public static TLV Read(byte[] d, int pos)
    {
        if (pos < 0 || pos + 2 > d.Length)
            throw new FormatException("DER truncated");

        byte tag = d[pos];
        int l = d[pos + 1];
        if (l < 0x80)
        {
            if (pos + 2 + l > d.Length)
                throw new FormatException("DER length past end");
            return new TLV(tag, 2, l, pos);
        }

        int n = l & 0x7F;
        if (n < 1 || n > 4 || pos + 2 + n > d.Length)
            throw new FormatException("DER bad length");

        int len = 0;
        for (int i = 0; i < n; i++)
        {
            len = (len << 8) | d[pos + 2 + i];
        }

        if (pos + 2 + n + len > d.Length)
            throw new FormatException("DER length past end");

        return new TLV(tag, 2 + n, len, pos);
    }

    public static List<TLV> Children(byte[] d, TLV t)
    {
        var outList = new List<TLV>();
        int p = t.Offset + t.HeaderLength;
        int end = t.End;
        while (p < end)
        {
            var c = Read(d, p);
            outList.Add(c);
            p = c.End;
        }
        return outList;
    }

    public static byte[] Content(byte[] d, TLV t)
    {
        var res = new byte[t.Length];
        Buffer.BlockCopy(d, t.ContentOffset, res, 0, t.Length);
        return res;
    }

    public static byte[] Full(byte[] d, TLV t)
    {
        var res = new byte[t.TotalLength];
        Buffer.BlockCopy(d, t.Offset, res, 0, t.TotalLength);
        return res;
    }

    public sealed class ByteArrayComparer : IComparer<byte[]>
    {
        public int Compare(byte[]? x, byte[]? y)
        {
            if (ReferenceEquals(x, y)) return 0;
            if (x == null) return -1;
            if (y == null) return 1;
            int len = Math.Min(x.Length, y.Length);
            for (int i = 0; i < len; i++)
            {
                int c = x[i].CompareTo(y[i]);
                if (c != 0) return c;
            }
            return x.Length.CompareTo(y.Length);
        }
    }
}

public static class PemHelper
{
    public static byte[]? GetBody(string text, string label)
    {
        string begin = $"-----BEGIN {label}-----";
        string end = $"-----END {label}-----";

        int bIdx = text.IndexOf(begin, StringComparison.Ordinal);
        if (bIdx < 0) return null;

        int eIdx = text.IndexOf(end, bIdx + begin.Length, StringComparison.Ordinal);
        if (eIdx < 0) return null;

        string inner = text.Substring(bIdx + begin.Length, eIdx - (bIdx + begin.Length))
                           .Replace("\r", "")
                           .Replace("\n", "")
                           .Trim();

        try
        {
            return Convert.FromBase64String(inner);
        }
        catch
        {
            return null;
        }
    }

    public static string ToPem(byte[] data, string label)
    {
        string b64 = Convert.ToBase64String(data);
        var sb = new StringBuilder();
        sb.AppendLine($"-----BEGIN {label}-----");
        for (int i = 0; i < b64.Length; i += 64)
        {
            sb.AppendLine(b64.Substring(i, Math.Min(64, b64.Length - i)));
        }
        sb.AppendLine($"-----END {label}-----");
        return sb.ToString();
    }
}

