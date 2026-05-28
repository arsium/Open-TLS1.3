namespace TLS;

using System.Buffers;

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

    public static void WriteUInt32(Span<byte> dest, uint value)
    {
        dest[0] = (byte)(value >> 24);
        dest[1] = (byte)(value >> 16);
        dest[2] = (byte)(value >> 8);
        dest[3] = (byte)value;
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

    // ---- IBufferWriter<byte> overloads (for ArrayBufferWriter<byte> / pooled writers) ----
    // These mirror the MemoryStream overloads above. They exist so HandshakeMessages can
    // build wire-format buffers without going through MemoryStream + ToArray.

    public static void WriteByte(IBufferWriter<byte> w, byte value)
    {
        var s = w.GetSpan(1);
        s[0] = value;
        w.Advance(1);
    }

    public static void WriteUInt16(IBufferWriter<byte> w, ushort value)
    {
        var s = w.GetSpan(2);
        s[0] = (byte)(value >> 8);
        s[1] = (byte)value;
        w.Advance(2);
    }

    public static void WriteUInt24(IBufferWriter<byte> w, uint value)
    {
        var s = w.GetSpan(3);
        s[0] = (byte)(value >> 16);
        s[1] = (byte)(value >> 8);
        s[2] = (byte)value;
        w.Advance(3);
    }

    public static void WriteUInt32(IBufferWriter<byte> w, uint value)
    {
        var s = w.GetSpan(4);
        s[0] = (byte)(value >> 24);
        s[1] = (byte)(value >> 16);
        s[2] = (byte)(value >> 8);
        s[3] = (byte)value;
        w.Advance(4);
    }

    public static void WriteBytes(IBufferWriter<byte> w, ReadOnlySpan<byte> value)
    {
        if (value.IsEmpty) return;
        value.CopyTo(w.GetSpan(value.Length));
        w.Advance(value.Length);
    }

    /// <summary>Read exactly <paramref name="count"/> bytes from the stream, blocking until available.</summary>
    public static byte[] ReadExact(Stream stream, int count)
    {
        byte[] buffer = new byte[count];
        ReadExactInto(stream, buffer.AsSpan(0, count));
        return buffer;
    }

    /// <summary>Asynchronously read exactly <paramref name="count"/> bytes from the stream.</summary>
    public static async Task<byte[]> ReadExactAsync(Stream stream, int count, CancellationToken ct = default)
    {
        byte[] buffer = new byte[count];
        await ReadExactIntoAsync(stream, buffer.AsMemory(0, count), ct).ConfigureAwait(false);
        return buffer;
    }

    /// <summary>Read exactly <c>buffer.Length</c> bytes from the stream into a caller-owned span
    /// (typically rented from <see cref="System.Buffers.ArrayPool{T}"/>). Throws on EOF.</summary>
    public static void ReadExactInto(Stream stream, Span<byte> buffer)
    {
        int offset = 0;
        while (offset < buffer.Length)
        {
            int read = stream.Read(buffer.Slice(offset));
            if (read == 0)
                throw new TlsException(AlertDescription.UnexpectedMessage, "Connection closed unexpectedly");
            offset += read;
        }
    }

    /// <summary>Async variant of <see cref="ReadExactInto"/>. <see cref="Memory{T}"/> (not Span)
    /// because Span can't cross await boundaries.</summary>
    public static async Task ReadExactIntoAsync(Stream stream, Memory<byte> buffer, CancellationToken ct = default)
    {
        int offset = 0;
        while (offset < buffer.Length)
        {
            int read = await stream.ReadAsync(buffer.Slice(offset), ct).ConfigureAwait(false);
            if (read == 0)
                throw new TlsException(AlertDescription.UnexpectedMessage, "Connection closed unexpectedly");
            offset += read;
        }
    }
}
