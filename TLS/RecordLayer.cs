namespace TLS;

/// <summary>
/// TLS 1.3 record layer — reads/writes TLS records and handles AEAD encryption.
/// Encrypted records are wrapped as ContentType.ApplicationData with the real
/// content type appended to the plaintext before encryption.
/// </summary>
public sealed class RecordLayer
{
    private readonly Stream _stream;
    private AeadCipher? _readCipher;
    private AeadCipher? _writeCipher;

    /// <summary>
    /// Record padding block size (RFC 8446 §5.4). When > 0, inner plaintext is padded
    /// with zeros to the next multiple of this value for traffic analysis resistance.
    /// 0 = no padding (default).
    /// </summary>
    public int PaddingBlockSize { get; set; }

    public RecordLayer(Stream stream)
    {
        _stream = stream;
    }

    public void SetReadCipher(AeadCipher cipher)
    {
        _readCipher?.Dispose();
        _readCipher = cipher;
    }

    public void SetWriteCipher(AeadCipher cipher)
    {
        _writeCipher?.Dispose();
        _writeCipher = cipher;
    }

    /// <summary>Remove the write cipher, reverting to plaintext writes (used when HRR invalidates early keys).</summary>
    public void ClearWriteCipher()
    {
        _writeCipher?.Dispose();
        _writeCipher = null;
    }

    /// <summary>Read one TLS record, decrypting if a read cipher is active.</summary>
    public (ContentType type, byte[] payload) ReadRecord()
    {
        byte[] header = BinaryHelper.ReadExact(_stream, 5);
        var outerType = (ContentType)header[0];
        ushort length = BinaryHelper.ReadUInt16(header.AsSpan(3));

        if (length > TlsConst.MaxCiphertextLength)
            throw new TlsException(AlertDescription.RecordOverflow, $"Record too large: {length}");

        byte[] payload = BinaryHelper.ReadExact(_stream, length);

        if (_readCipher != null && outerType == ContentType.ApplicationData)
        {
            byte[] plaintext = _readCipher.Decrypt(payload, header);

            // Strip trailing zero-padding and extract inner content type (last non-zero byte)
            int end = plaintext.Length - 1;
            while (end >= 0 && plaintext[end] == 0) end--;
            if (end < 0)
                throw new TlsException(AlertDescription.UnexpectedMessage, "Empty inner plaintext");

            byte rawType = plaintext[end];
            if (rawType != (byte)ContentType.ChangeCipherSpec && rawType != (byte)ContentType.Alert
                && rawType != (byte)ContentType.Handshake && rawType != (byte)ContentType.ApplicationData)
                throw new TlsException(AlertDescription.UnexpectedMessage, $"Invalid inner content type: {rawType}");
            return ((ContentType)rawType, plaintext[..end]);
        }

        return (outerType, payload);
    }

    /// <summary>Write one TLS record, encrypting if a write cipher is active.</summary>
    public void WriteRecord(ContentType type, byte[] data)
    {
        if (_writeCipher != null)
        {
            // Fragment to respect RFC 8446 Section 5.1 record size limits
            int offset = 0;
            while (offset < data.Length)
            {
                int chunkLen = Math.Min(data.Length - offset, TlsConst.MaxPlaintextLength);

                // Build inner plaintext: chunk ‖ content_type ‖ padding_zeros
                int innerLen = chunkLen + 1; // +1 for content type
                if (PaddingBlockSize > 0)
                    innerLen = ((innerLen + PaddingBlockSize - 1) / PaddingBlockSize) * PaddingBlockSize;
                byte[] inner = new byte[innerLen];
                Buffer.BlockCopy(data, offset, inner, 0, chunkLen);
                inner[chunkLen] = (byte)type;

                int encLen = inner.Length + TlsConst.AeadTagLength;
                byte[] header = BuildHeader(ContentType.ApplicationData, (ushort)encLen);

                byte[] encrypted = _writeCipher.Encrypt(inner, header);

                _stream.Write(header);
                _stream.Write(encrypted);
                offset += chunkLen;
            }
            _stream.Flush();
        }
        else
        {
            // Plaintext — fragment if needed
            int offset = 0;
            while (offset < data.Length)
            {
                int chunkLen = Math.Min(data.Length - offset, TlsConst.MaxPlaintextLength);
                byte[] header = BuildHeader(type, (ushort)chunkLen);

                _stream.Write(header);
                _stream.Write(data, offset, chunkLen);
                offset += chunkLen;
            }
            _stream.Flush();
        }
    }

    /// <summary>Send a dummy ChangeCipherSpec for middlebox compatibility.</summary>
    public void WriteChangeCipherSpec()
    {
        byte[] header = new byte[5];
        header[0] = (byte)ContentType.ChangeCipherSpec;
        BinaryHelper.WriteUInt16(header.AsSpan(1), TlsConst.LegacyVersion);
        BinaryHelper.WriteUInt16(header.AsSpan(3), 1);
        _stream.Write(header);
        _stream.WriteByte(0x01);
        _stream.Flush();
    }

    /// <summary>
    /// Try to read and decrypt a record. Returns null if AEAD decryption fails
    /// (used for trial decryption to skip rejected 0-RTT early data per RFC 8446 §4.2.10).
    /// On failure, the cipher sequence number is NOT advanced.
    /// CCS records are returned as-is (no decryption attempted).
    /// </summary>
    public (ContentType type, byte[] payload)? TryReadRecord()
    {
        byte[] header = BinaryHelper.ReadExact(_stream, 5);
        var outerType = (ContentType)header[0];
        ushort length = BinaryHelper.ReadUInt16(header.AsSpan(3));

        if (length > TlsConst.MaxCiphertextLength)
            throw new TlsException(AlertDescription.RecordOverflow, $"Record too large: {length}");

        byte[] payload = BinaryHelper.ReadExact(_stream, length);

        if (_readCipher != null && outerType == ContentType.ApplicationData)
        {
            if (!_readCipher.TryDecrypt(payload, header, out byte[]? plaintext))
                return null;

            int end = plaintext!.Length - 1;
            while (end >= 0 && plaintext[end] == 0) end--;
            if (end < 0) return null;

            byte rawType = plaintext[end];
            return ((ContentType)rawType, plaintext[..end]);
        }

        return (outerType, payload);
    }

    /// <summary>Async version of TryReadRecord for trial decryption.</summary>
    public async Task<(ContentType type, byte[] payload)?> TryReadRecordAsync(CancellationToken ct = default)
    {
        byte[] header = await BinaryHelper.ReadExactAsync(_stream, 5, ct).ConfigureAwait(false);
        var outerType = (ContentType)header[0];
        ushort length = BinaryHelper.ReadUInt16(header.AsSpan(3));

        if (length > TlsConst.MaxCiphertextLength)
            throw new TlsException(AlertDescription.RecordOverflow, $"Record too large: {length}");

        byte[] payload = await BinaryHelper.ReadExactAsync(_stream, length, ct).ConfigureAwait(false);

        if (_readCipher != null && outerType == ContentType.ApplicationData)
        {
            if (!_readCipher.TryDecrypt(payload, header, out byte[]? plaintext))
                return null;

            int end = plaintext!.Length - 1;
            while (end >= 0 && plaintext[end] == 0) end--;
            if (end < 0) return null;

            byte rawType = plaintext[end];
            return ((ContentType)rawType, plaintext[..end]);
        }

        return (outerType, payload);
    }

    // ================================================================
    //  Async methods
    // ================================================================

    /// <summary>Read one TLS record asynchronously, decrypting if a read cipher is active.</summary>
    public async Task<(ContentType type, byte[] payload)> ReadRecordAsync(CancellationToken ct = default)
    {
        byte[] header = await BinaryHelper.ReadExactAsync(_stream, 5, ct).ConfigureAwait(false);
        var outerType = (ContentType)header[0];
        ushort length = BinaryHelper.ReadUInt16(header.AsSpan(3));

        if (length > TlsConst.MaxCiphertextLength)
            throw new TlsException(AlertDescription.RecordOverflow, $"Record too large: {length}");

        byte[] payload = await BinaryHelper.ReadExactAsync(_stream, length, ct).ConfigureAwait(false);

        if (_readCipher != null && outerType == ContentType.ApplicationData)
        {
            byte[] plaintext = _readCipher.Decrypt(payload, header);

            int end = plaintext.Length - 1;
            while (end >= 0 && plaintext[end] == 0) end--;
            if (end < 0)
                throw new TlsException(AlertDescription.UnexpectedMessage, "Empty inner plaintext");

            byte rawType = plaintext[end];
            if (rawType != (byte)ContentType.ChangeCipherSpec && rawType != (byte)ContentType.Alert
                && rawType != (byte)ContentType.Handshake && rawType != (byte)ContentType.ApplicationData)
                throw new TlsException(AlertDescription.UnexpectedMessage, $"Invalid inner content type: {rawType}");
            return ((ContentType)rawType, plaintext[..end]);
        }

        return (outerType, payload);
    }

    /// <summary>Write one TLS record asynchronously, encrypting if a write cipher is active.</summary>
    public async Task WriteRecordAsync(ContentType type, byte[] data, CancellationToken ct = default)
    {
        if (_writeCipher != null)
        {
            // Fragment to respect RFC 8446 Section 5.1 record size limits
            int offset = 0;
            while (offset < data.Length)
            {
                int chunkLen = Math.Min(data.Length - offset, TlsConst.MaxPlaintextLength);

                int innerLen = chunkLen + 1;
                if (PaddingBlockSize > 0)
                    innerLen = ((innerLen + PaddingBlockSize - 1) / PaddingBlockSize) * PaddingBlockSize;
                byte[] inner = new byte[innerLen];
                Buffer.BlockCopy(data, offset, inner, 0, chunkLen);
                inner[chunkLen] = (byte)type;

                int encLen = inner.Length + TlsConst.AeadTagLength;
                byte[] header = BuildHeader(ContentType.ApplicationData, (ushort)encLen);

                byte[] encrypted = _writeCipher.Encrypt(inner, header);

                await _stream.WriteAsync(header, ct).ConfigureAwait(false);
                await _stream.WriteAsync(encrypted, ct).ConfigureAwait(false);
                offset += chunkLen;
            }
            await _stream.FlushAsync(ct).ConfigureAwait(false);
        }
        else
        {
            int offset = 0;
            while (offset < data.Length)
            {
                int chunkLen = Math.Min(data.Length - offset, TlsConst.MaxPlaintextLength);
                byte[] header = BuildHeader(type, (ushort)chunkLen);

                await _stream.WriteAsync(header, ct).ConfigureAwait(false);
                await _stream.WriteAsync(data.AsMemory(offset, chunkLen), ct).ConfigureAwait(false);
                offset += chunkLen;
            }
            await _stream.FlushAsync(ct).ConfigureAwait(false);
        }
    }

    /// <summary>Send a dummy ChangeCipherSpec asynchronously for middlebox compatibility.</summary>
    public async Task WriteChangeCipherSpecAsync(CancellationToken ct = default)
    {
        byte[] record = new byte[6];
        record[0] = (byte)ContentType.ChangeCipherSpec;
        BinaryHelper.WriteUInt16(record.AsSpan(1), TlsConst.LegacyVersion);
        BinaryHelper.WriteUInt16(record.AsSpan(3), 1);
        record[5] = 0x01;
        await _stream.WriteAsync(record, ct).ConfigureAwait(false);
        await _stream.FlushAsync(ct).ConfigureAwait(false);
    }

    private byte[] BuildHeader(ContentType type, ushort payloadLen)
    {
        byte[] h = new byte[5];
        h[0] = (byte)type;
        // RFC 8446 §5.1: record layer version is always 0x0303 (TLS 1.2)
        ushort version = TlsConst.LegacyVersion;
        BinaryHelper.WriteUInt16(h.AsSpan(1), version);
        BinaryHelper.WriteUInt16(h.AsSpan(3), payloadLen);
        return h;
    }
}
