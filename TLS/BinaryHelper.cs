namespace TLS;

/// <summary>Big-endian binary read/write helpers for TLS wire format.</summary>
public static class BinaryHelper
{
    public static ushort ReadUInt16(ReadOnlySpan<byte> data) =>
        (ushort)((data[0] << 8) | data[1]);

    public static uint ReadUInt24(ReadOnlySpan<byte> data) =>
        (uint)((data[0] << 16) | (data[1] << 8) | data[2]);

    public static uint ReadUInt32(ReadOnlySpan<byte> data) =>
        ((uint)data[0] << 24) | ((uint)data[1] << 16) | ((uint)data[2] << 8) | data[3];

    public static void WriteUInt16(Span<byte> dest, ushort value)
    {
        dest[0] = (byte)(value >> 8);
        dest[1] = (byte)value;
    }

    public static void WriteUInt24(Span<byte> dest, uint value)
    {
        dest[0] = (byte)(value >> 16);
        dest[1] = (byte)(value >> 8);
        dest[2] = (byte)value;
    }

    public static void WriteUInt16(MemoryStream ms, ushort value)
    {
        ms.WriteByte((byte)(value >> 8));
        ms.WriteByte((byte)value);
    }

    public static void WriteUInt24(MemoryStream ms, uint value)
    {
        ms.WriteByte((byte)(value >> 16));
        ms.WriteByte((byte)(value >> 8));
        ms.WriteByte((byte)value);
    }

    public static void WriteUInt32(MemoryStream ms, uint value)
    {
        ms.WriteByte((byte)(value >> 24));
        ms.WriteByte((byte)(value >> 16));
        ms.WriteByte((byte)(value >> 8));
        ms.WriteByte((byte)value);
    }

    /// <summary>Read exactly <paramref name="count"/> bytes from the stream, blocking until available.</summary>
    public static byte[] ReadExact(Stream stream, int count)
    {
        byte[] buffer = new byte[count];
        int offset = 0;
        while (offset < count)
        {
            int read = stream.Read(buffer, offset, count - offset);
            if (read == 0)
                throw new TlsException(AlertDescription.UnexpectedMessage, "Connection closed unexpectedly");
            offset += read;
        }
        return buffer;
    }

    /// <summary>Asynchronously read exactly <paramref name="count"/> bytes from the stream.</summary>
    public static async Task<byte[]> ReadExactAsync(Stream stream, int count, CancellationToken ct = default)
    {
        byte[] buffer = new byte[count];
        int offset = 0;
        while (offset < count)
        {
            int read = await stream.ReadAsync(buffer, offset, count - offset, ct).ConfigureAwait(false);
            if (read == 0)
                throw new TlsException(AlertDescription.UnexpectedMessage, "Connection closed unexpectedly");
            offset += read;
        }
        return buffer;
    }
}
