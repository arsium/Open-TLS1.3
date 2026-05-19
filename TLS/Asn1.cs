namespace TLS;

using System.Numerics;
using System.Text;

/// <summary>Minimal ASN.1 DER encoder/decoder for X.509 certificate generation.</summary>
public static class Asn1
{
    // ----- Tag constants -----
    public const byte TagInteger = 0x02;
    public const byte TagBitString = 0x03;
    public const byte TagOctetString = 0x04;
    public const byte TagNull = 0x05;
    public const byte TagOid = 0x06;
    public const byte TagUtf8String = 0x0C;
    public const byte TagPrintableString = 0x13;
    public const byte TagUtcTime = 0x17;
    public const byte TagGeneralizedTime = 0x18;
    public const byte TagSequence = 0x30;
    public const byte TagSet = 0x31;

    // ----- Encoder -----

    public static byte[] Sequence(params byte[][] items) =>
        Wrap(TagSequence, Concat(items));

    public static byte[] Set(params byte[][] items) =>
        Wrap(TagSet, Concat(items));

    public static byte[] Integer(int value) => Integer(new BigInteger(value));

    public static byte[] Integer(BigInteger value)
    {
        byte[] raw = value.ToByteArray(); // little-endian, signed
        Array.Reverse(raw);              // convert to big-endian DER
        return Wrap(TagInteger, raw);
    }

    /// <summary>Wrap a big-endian unsigned byte array as an ASN.1 INTEGER.</summary>
    public static byte[] IntegerRaw(byte[] bigEndianUnsigned)
    {
        byte[] val;
        if (bigEndianUnsigned.Length > 0 && (bigEndianUnsigned[0] & 0x80) != 0)
        {
            val = new byte[bigEndianUnsigned.Length + 1];
            Buffer.BlockCopy(bigEndianUnsigned, 0, val, 1, bigEndianUnsigned.Length);
        }
        else
        {
            val = bigEndianUnsigned;
        }
        return Wrap(TagInteger, val);
    }

    public static byte[] BitString(byte[] data)
    {
        byte[] content = new byte[data.Length + 1];
        content[0] = 0; // unused bits = 0
        Buffer.BlockCopy(data, 0, content, 1, data.Length);
        return Wrap(TagBitString, content);
    }

    public static byte[] OctetString(byte[] data) =>
        Wrap(TagOctetString, data);

    public static byte[] Null() => new byte[] { TagNull, 0x00 };

    public static byte[] Oid(string oid)
    {
        string[] parts = oid.Split('.');
        int[] nums = new int[parts.Length];
        for (int i = 0; i < parts.Length; i++)
            nums[i] = int.Parse(parts[i]);

        using var ms = new MemoryStream();
        ms.WriteByte((byte)(40 * nums[0] + nums[1]));
        for (int i = 2; i < nums.Length; i++)
            WriteBase128(ms, nums[i]);

        return Wrap(TagOid, ms.ToArray());
    }

    public static byte[] Utf8String(string s) =>
        Wrap(TagUtf8String, Encoding.UTF8.GetBytes(s));

    public static byte[] UtcTime(DateTime dt)
    {
        var u = dt.ToUniversalTime();
        int yy = u.Year % 100;
        byte[] ascii = Encoding.ASCII.GetBytes(
            $"{yy:D2}{u.Month:D2}{u.Day:D2}{u.Hour:D2}{u.Minute:D2}{u.Second:D2}Z");
        return Wrap(TagUtcTime, ascii);
    }

    public static byte[] Explicit(int tagNum, byte[] content) =>
        Wrap((byte)(0xA0 | tagNum), content);

    public static byte[] Wrap(byte tag, byte[] content)
    {
        using var ms = new MemoryStream();
        ms.WriteByte(tag);
        WriteLength(ms, content.Length);
        ms.Write(content);
        return ms.ToArray();
    }

    public static byte[] Concat(params byte[][] arrays)
    {
        int total = 0;
        for (int i = 0; i < arrays.Length; i++) total += arrays[i].Length;
        byte[] result = new byte[total];
        int offset = 0;
        for (int i = 0; i < arrays.Length; i++)
        {
            Buffer.BlockCopy(arrays[i], 0, result, offset, arrays[i].Length);
            offset += arrays[i].Length;
        }
        return result;
    }

    private static void WriteLength(MemoryStream ms, int length)
    {
        if (length < 0x80)
        {
            ms.WriteByte((byte)length);
        }
        else if (length < 0x100)
        {
            ms.WriteByte(0x81);
            ms.WriteByte((byte)length);
        }
        else if (length < 0x10000)
        {
            ms.WriteByte(0x82);
            ms.WriteByte((byte)(length >> 8));
            ms.WriteByte((byte)length);
        }
        else
        {
            ms.WriteByte(0x83);
            ms.WriteByte((byte)(length >> 16));
            ms.WriteByte((byte)(length >> 8));
            ms.WriteByte((byte)length);
        }
    }

    private static void WriteBase128(MemoryStream ms, int value)
    {
        if (value < 0x80) { ms.WriteByte((byte)value); return; }

        var bytes = new List<byte>();
        int v = value;
        while (v > 0)
        {
            bytes.Insert(0, (byte)(v & 0x7F));
            v >>= 7;
        }
        for (int i = 0; i < bytes.Count - 1; i++)
            bytes[i] |= 0x80;

        foreach (byte b in bytes) ms.WriteByte(b);
    }

    // ----- Decoder -----

    public static (byte tag, byte[] value, int consumed) ReadTlv(ReadOnlySpan<byte> data)
    {
        if (data.Length < 2)
            throw new TlsException(AlertDescription.DecodeError, "ASN.1 TLV too short");

        int pos = 0;
        byte tag = data[pos++];

        int length;
        if ((data[pos] & 0x80) == 0)
        {
            length = data[pos++];
        }
        else
        {
            int numBytes = data[pos++] & 0x7F;
            if (pos + numBytes > data.Length)
                throw new TlsException(AlertDescription.DecodeError, "ASN.1 length bytes exceed data");
            length = 0;
            for (int i = 0; i < numBytes; i++)
                length = (length << 8) | data[pos++];
        }

        if (pos + length > data.Length)
            throw new TlsException(AlertDescription.DecodeError,
                $"ASN.1 value length {length} exceeds available data {data.Length - pos}");

        byte[] value = data.Slice(pos, length).ToArray();
        return (tag, value, pos + length);
    }

    public static List<(byte tag, byte[] value)> ReadSequenceItems(byte[] seqValue)
    {
        var items = new List<(byte, byte[])>();
        int pos = 0;
        while (pos < seqValue.Length)
        {
            var (tag, value, consumed) = ReadTlv(seqValue.AsSpan(pos));
            items.Add((tag, value));
            pos += consumed;
        }
        return items;
    }
}
