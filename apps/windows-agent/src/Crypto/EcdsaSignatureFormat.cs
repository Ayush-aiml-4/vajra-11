using System.Security.Cryptography;

namespace Vajra.WindowsAgent.Crypto;

/// <summary>
/// Node.js crypto.verify for ECDSA expects DER-encoded signatures.
/// .NET ECDsa.SignData returns IEEE P1363 (r||s). Convert P-256 signatures to DER.
/// </summary>
public static class EcdsaSignatureFormat
{
    /// <summary>Convert IEEE P1363 (64-byte r||s for P-256) to ASN.1 DER.</summary>
    public static byte[] P1363ToDer(byte[] p1363)
    {
        if (p1363.Length % 2 != 0)
            throw new ArgumentException("P1363 signature length must be even.", nameof(p1363));
        var half = p1363.Length / 2;
        var r = new byte[half];
        var s = new byte[half];
        Buffer.BlockCopy(p1363, 0, r, 0, half);
        Buffer.BlockCopy(p1363, half, s, 0, half);
        return EncodeDerIntegerPair(r, s);
    }

    private static byte[] EncodeDerIntegerPair(byte[] r, byte[] s)
    {
        var rInt = EncodeDerInteger(r);
        var sInt = EncodeDerInteger(s);
        var seqLen = rInt.Length + sInt.Length;
        using var ms = new MemoryStream();
        ms.WriteByte(0x30); // SEQUENCE
        WriteDerLength(ms, seqLen);
        ms.Write(rInt);
        ms.Write(sInt);
        return ms.ToArray();
    }

    private static byte[] EncodeDerInteger(byte[] unsignedBigEndian)
    {
        // Strip leading zeros but keep one zero if high bit set (sign bit)
        var start = 0;
        while (start < unsignedBigEndian.Length - 1 && unsignedBigEndian[start] == 0)
            start++;
        var needsPad = (unsignedBigEndian[start] & 0x80) != 0;
        var len = unsignedBigEndian.Length - start + (needsPad ? 1 : 0);
        var result = new byte[2 + len];
        result[0] = 0x02; // INTEGER
        result[1] = (byte)len;
        var offset = 2;
        if (needsPad) result[offset++] = 0x00;
        Buffer.BlockCopy(unsignedBigEndian, start, result, offset, unsignedBigEndian.Length - start);
        return result;
    }

    private static void WriteDerLength(MemoryStream ms, int length)
    {
        if (length < 0x80)
        {
            ms.WriteByte((byte)length);
        }
        else
        {
            // Sufficient for ECDSA P-256 signatures
            ms.WriteByte(0x81);
            ms.WriteByte((byte)length);
        }
    }
}
