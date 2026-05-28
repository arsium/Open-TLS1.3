namespace TLS;

using System.Buffers;

/// <summary>
/// TLS 1.3 record layer — reads/writes TLS records and handles AEAD encryption.
/// Encrypted records are wrapped as ContentType.ApplicationData with the real
/// content type appended to the plaintext before encryption.
/// </summary>
public sealed class RecordLayer : IDisposable
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

    /// <summary>RFC 8449: max plaintext bytes per outgoing record (peer's record_size_limit − 1). Default 2^14.</summary>
    public int MaxSendPlaintext { get; set; } = TlsConst.MaxPlaintextLength;

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

    public void Dispose()
    {
        _readCipher?.Dispose();
        _readCipher = null;
        _writeCipher?.Dispose();
        _writeCipher = null;
    }

    /// <summary>RFC 8446 §5.5: true when the current write cipher has reached the rekey watermark.</summary>
    public bool WriteCipherNeedsKeyUpdate => _writeCipher is { NeedsKeyUpdate: true };

    /// <summary>
    /// Outcome of <see cref="ReadRecordInto"/> / <see cref="ReadRecordIntoAsync"/>.
    ///
    /// <para>If <see cref="LeasedBuffer"/> is null, the record's plaintext was written
    /// directly into the caller-provided destination span at <c>[0, Length)</c> — no
    /// allocation, no copy.</para>
    ///
    /// <para>If <see cref="LeasedBuffer"/> is non-null, the destination was either too
    /// small for the record's plaintext (in which case the lease holds the full record
    /// at <c>[0, Length)</c>) or this was an unencrypted record (the lease holds the
    /// raw payload). Either way the caller MUST <c>Array.Clear</c> the valid range and
    /// return the lease to <c>ArrayPool&lt;byte&gt;.Shared</c> when done consuming.</para>
    /// </summary>
    public readonly struct RecordIntoResult
    {
        public readonly ContentType Type;
        public readonly int Length;
        public readonly byte[]? LeasedBuffer;
        public RecordIntoResult(ContentType type, int length, byte[]? leasedBuffer)
        { Type = type; Length = length; LeasedBuffer = leasedBuffer; }
    }

    /// <summary>
    /// Read the next TLS record. For encrypted ApplicationData records that fit in
    /// <paramref name="destination"/>, decrypts directly into the caller's span — no
    /// plaintext byte[] allocation. Otherwise leases a pool buffer (see
    /// <see cref="RecordIntoResult"/>).
    /// </summary>
    public RecordIntoResult ReadRecordInto(Span<byte> destination)
    {
        byte[] header = BinaryHelper.ReadExact(_stream, 5);
        var outerType = (ContentType)header[0];
        ushort recordLen = BinaryHelper.ReadUInt16(header.AsSpan(3));

        if (recordLen > TlsConst.MaxCiphertextLength)
            throw new TlsException(AlertDescription.RecordOverflow, $"Record too large: {recordLen}");

        if (_readCipher != null && outerType == ContentType.ApplicationData)
        {
            int ctLen = recordLen - _readCipher.TagLength;
            // RFC 8446 §5.2: a record too short to hold the AEAD tag can't be deprotected.
            // Fail with bad_record_mac instead of letting the negative-length Slice / Rent
            // below throw a raw ArgumentOutOfRangeException up to the application.
            if (ctLen < 0)
                throw new TlsException(AlertDescription.BadRecordMac, "Record too short for AEAD tag");
            byte[] encRented = ArrayPool<byte>.Shared.Rent(recordLen);
            byte[]? ptRented = null;
            try
            {
                BinaryHelper.ReadExactInto(_stream, encRented.AsSpan(0, recordLen));

                if (destination.Length >= ctLen)
                {
                    // Direct path: decrypt straight into the caller's destination.
                    _readCipher.DecryptInto(
                        new ReadOnlySpan<byte>(encRented, 0, recordLen),
                        header,
                        destination.Slice(0, ctLen));

                    int end = ctLen - 1;
                    while (end >= 0 && destination[end] == 0) end--;
                    if (end < 0)
                        throw new TlsException(AlertDescription.UnexpectedMessage, "Empty inner plaintext");

                    byte rawType = destination[end];
                    if (rawType != (byte)ContentType.ChangeCipherSpec && rawType != (byte)ContentType.Alert
                        && rawType != (byte)ContentType.Handshake && rawType != (byte)ContentType.ApplicationData)
                        throw new TlsException(AlertDescription.UnexpectedMessage, $"Invalid inner content type: {rawType}");

                    return new RecordIntoResult((ContentType)rawType, end, leasedBuffer: null);
                }

                // Overflow path: caller's destination is too small. Lease a plaintext
                // buffer; caller will copy out what fits and stash / process the rest.
                ptRented = ArrayPool<byte>.Shared.Rent(ctLen);
                _readCipher.DecryptInto(
                    new ReadOnlySpan<byte>(encRented, 0, recordLen),
                    header,
                    ptRented.AsSpan(0, ctLen));

                int end2 = ctLen - 1;
                while (end2 >= 0 && ptRented[end2] == 0) end2--;
                if (end2 < 0)
                    throw new TlsException(AlertDescription.UnexpectedMessage, "Empty inner plaintext");

                byte rawType2 = ptRented[end2];
                if (rawType2 != (byte)ContentType.ChangeCipherSpec && rawType2 != (byte)ContentType.Alert
                    && rawType2 != (byte)ContentType.Handshake && rawType2 != (byte)ContentType.ApplicationData)
                    throw new TlsException(AlertDescription.UnexpectedMessage, $"Invalid inner content type: {rawType2}");

                var result = new RecordIntoResult((ContentType)rawType2, end2, leasedBuffer: ptRented);
                ptRented = null; // ownership transferred to caller; suppress finally release
                return result;
            }
            finally
            {
                Array.Clear(encRented, 0, recordLen);
                ArrayPool<byte>.Shared.Return(encRented);
                if (ptRented != null)
                {
                    Array.Clear(ptRented, 0, ctLen);
                    ArrayPool<byte>.Shared.Return(ptRented);
                }
            }
        }

        // Unencrypted path (rare — only during early handshake before keys are installed).
        // Always lease, for uniform "LeasedBuffer non-null = caller releases" semantics.
        byte[] plainRented = ArrayPool<byte>.Shared.Rent(recordLen);
        bool transferred = false;
        try
        {
            BinaryHelper.ReadExactInto(_stream, plainRented.AsSpan(0, recordLen));
            var result = new RecordIntoResult(outerType, recordLen, leasedBuffer: plainRented);
            transferred = true;
            return result;
        }
        finally
        {
            if (!transferred)
            {
                Array.Clear(plainRented, 0, recordLen);
                ArrayPool<byte>.Shared.Return(plainRented);
            }
        }
    }

    /// <summary>Async equivalent of <see cref="ReadRecordInto"/>. Takes
    /// <see cref="Memory{T}"/> because spans can't cross await boundaries.</summary>
    public async Task<RecordIntoResult> ReadRecordIntoAsync(Memory<byte> destination, CancellationToken ct = default)
    {
        byte[] header = await BinaryHelper.ReadExactAsync(_stream, 5, ct).ConfigureAwait(false);
        var outerType = (ContentType)header[0];
        ushort recordLen = BinaryHelper.ReadUInt16(header.AsSpan(3));

        if (recordLen > TlsConst.MaxCiphertextLength)
            throw new TlsException(AlertDescription.RecordOverflow, $"Record too large: {recordLen}");

        if (_readCipher != null && outerType == ContentType.ApplicationData)
        {
            int ctLen = recordLen - _readCipher.TagLength;
            // RFC 8446 §5.2: a record too short to hold the AEAD tag can't be deprotected.
            // Fail with bad_record_mac instead of letting the negative-length Slice / Rent
            // below throw a raw ArgumentOutOfRangeException up to the application.
            if (ctLen < 0)
                throw new TlsException(AlertDescription.BadRecordMac, "Record too short for AEAD tag");
            byte[] encRented = ArrayPool<byte>.Shared.Rent(recordLen);
            byte[]? ptRented = null;
            try
            {
                await BinaryHelper.ReadExactIntoAsync(_stream, encRented.AsMemory(0, recordLen), ct).ConfigureAwait(false);

                if (destination.Length >= ctLen)
                {
                    var destSpan = destination.Span;
                    _readCipher.DecryptInto(
                        new ReadOnlySpan<byte>(encRented, 0, recordLen),
                        header,
                        destSpan.Slice(0, ctLen));

                    int end = ctLen - 1;
                    while (end >= 0 && destSpan[end] == 0) end--;
                    if (end < 0)
                        throw new TlsException(AlertDescription.UnexpectedMessage, "Empty inner plaintext");

                    byte rawType = destSpan[end];
                    if (rawType != (byte)ContentType.ChangeCipherSpec && rawType != (byte)ContentType.Alert
                        && rawType != (byte)ContentType.Handshake && rawType != (byte)ContentType.ApplicationData)
                        throw new TlsException(AlertDescription.UnexpectedMessage, $"Invalid inner content type: {rawType}");

                    return new RecordIntoResult((ContentType)rawType, end, leasedBuffer: null);
                }

                ptRented = ArrayPool<byte>.Shared.Rent(ctLen);
                _readCipher.DecryptInto(
                    new ReadOnlySpan<byte>(encRented, 0, recordLen),
                    header,
                    ptRented.AsSpan(0, ctLen));

                int end2 = ctLen - 1;
                while (end2 >= 0 && ptRented[end2] == 0) end2--;
                if (end2 < 0)
                    throw new TlsException(AlertDescription.UnexpectedMessage, "Empty inner plaintext");

                byte rawType2 = ptRented[end2];
                if (rawType2 != (byte)ContentType.ChangeCipherSpec && rawType2 != (byte)ContentType.Alert
                    && rawType2 != (byte)ContentType.Handshake && rawType2 != (byte)ContentType.ApplicationData)
                    throw new TlsException(AlertDescription.UnexpectedMessage, $"Invalid inner content type: {rawType2}");

                var result = new RecordIntoResult((ContentType)rawType2, end2, leasedBuffer: ptRented);
                ptRented = null;
                return result;
            }
            finally
            {
                Array.Clear(encRented, 0, recordLen);
                ArrayPool<byte>.Shared.Return(encRented);
                if (ptRented != null)
                {
                    Array.Clear(ptRented, 0, ctLen);
                    ArrayPool<byte>.Shared.Return(ptRented);
                }
            }
        }

        byte[] plainRented = ArrayPool<byte>.Shared.Rent(recordLen);
        bool transferred = false;
        try
        {
            await BinaryHelper.ReadExactIntoAsync(_stream, plainRented.AsMemory(0, recordLen), ct).ConfigureAwait(false);
            var result = new RecordIntoResult(outerType, recordLen, leasedBuffer: plainRented);
            transferred = true;
            return result;
        }
        finally
        {
            if (!transferred)
            {
                Array.Clear(plainRented, 0, recordLen);
                ArrayPool<byte>.Shared.Return(plainRented);
            }
        }
    }

    /// <summary>Read one TLS record, decrypting if a read cipher is active.</summary>
    public (ContentType type, byte[] payload) ReadRecord()
    {
        byte[] header = BinaryHelper.ReadExact(_stream, 5);
        var outerType = (ContentType)header[0];
        ushort length = BinaryHelper.ReadUInt16(header.AsSpan(3));

        if (length > TlsConst.MaxCiphertextLength)
            throw new TlsException(AlertDescription.RecordOverflow, $"Record too large: {length}");

        if (_readCipher != null && outerType == ContentType.ApplicationData)
        {
            // Pool both the encrypted payload buffer and the plaintext workspace; the
            // only remaining heap allocation per encrypted record read is the trimmed
            // payload byte[] we hand back to the caller.
            int ctLen = length - _readCipher.TagLength;
            // RFC 8446 §5.2: reject records too short to hold the AEAD tag with bad_record_mac
            // instead of throwing a raw ArgumentOutOfRangeException from ArrayPool.Rent below.
            if (ctLen < 0)
                throw new TlsException(AlertDescription.BadRecordMac, "Record too short for AEAD tag");
            byte[] encRented = ArrayPool<byte>.Shared.Rent(length);
            byte[] ptRented = ArrayPool<byte>.Shared.Rent(ctLen);
            try
            {
                BinaryHelper.ReadExactInto(_stream, encRented.AsSpan(0, length));
                _readCipher.DecryptInto(
                    new ReadOnlySpan<byte>(encRented, 0, length),
                    header,
                    ptRented.AsSpan(0, ctLen));

                // Strip trailing zero-padding and extract inner content type (last non-zero byte).
                int end = ctLen - 1;
                while (end >= 0 && ptRented[end] == 0) end--;
                if (end < 0)
                    throw new TlsException(AlertDescription.UnexpectedMessage, "Empty inner plaintext");

                byte rawType = ptRented[end];
                if (rawType != (byte)ContentType.ChangeCipherSpec && rawType != (byte)ContentType.Alert
                    && rawType != (byte)ContentType.Handshake && rawType != (byte)ContentType.ApplicationData)
                    throw new TlsException(AlertDescription.UnexpectedMessage, $"Invalid inner content type: {rawType}");

                byte[] payload = new byte[end];
                new ReadOnlySpan<byte>(ptRented, 0, end).CopyTo(payload);
                return ((ContentType)rawType, payload);
            }
            finally
            {
                Array.Clear(encRented, 0, length);
                ArrayPool<byte>.Shared.Return(encRented);
                Array.Clear(ptRented, 0, ctLen);
                ArrayPool<byte>.Shared.Return(ptRented);
            }
        }

        byte[] plaintext = BinaryHelper.ReadExact(_stream, length);
        return (outerType, plaintext);
    }

    /// <summary>Write one TLS record, encrypting if a write cipher is active.
    /// <c>data</c> is a span so callers can pass a pooled buffer or an array slice
    /// without first materialising a fresh <c>byte[]</c> (was the case before — see
    /// <c>TlsConnection.Write</c> which used to do <c>data[pos..(pos+chunk)]</c>).</summary>
    public void WriteRecord(ContentType type, ReadOnlySpan<byte> data)
    {
        if (_writeCipher != null)
        {
            // Fragment to respect RFC 8446 Section 5.1 record size limits
            int offset = 0;
            while (offset < data.Length)
            {
                int chunkLen = Math.Min(data.Length - offset, MaxSendPlaintext);

                // Build inner plaintext: chunk ‖ content_type ‖ padding_zeros. Pool the
                // intermediate buffer — at MaxPlaintextLength+1 (16385) bytes it's the
                // single biggest per-record allocation on the encrypt path.
                int innerLen = chunkLen + 1; // +1 for content type
                if (PaddingBlockSize > 0)
                    innerLen = ((innerLen + PaddingBlockSize - 1) / PaddingBlockSize) * PaddingBlockSize;
                byte[] innerRented = ArrayPool<byte>.Shared.Rent(innerLen);
                try
                {
                    data.Slice(offset, chunkLen).CopyTo(innerRented);
                    innerRented[chunkLen] = (byte)type;
                    // Zero the padding slot — the rented buffer may carry stale bytes.
                    if (innerLen > chunkLen + 1)
                        Array.Clear(innerRented, chunkLen + 1, innerLen - chunkLen - 1);

                    int encLen = innerLen + _writeCipher.TagLength;
                    byte[] header = BuildHeader(ContentType.ApplicationData, (ushort)encLen);

                    // Pool the ciphertext buffer too — at 16400 B per record on the bulk
                    // path this used to be the second-largest per-record allocation.
                    byte[] encRented = ArrayPool<byte>.Shared.Rent(encLen);
                    try
                    {
                        _writeCipher.EncryptInto(
                            new ReadOnlySpan<byte>(innerRented, 0, innerLen),
                            header,
                            encRented.AsSpan(0, encLen));
                        _stream.Write(header);
                        _stream.Write(encRented, 0, encLen);
                    }
                    finally
                    {
                        // Wipe before return — ciphertext is "public" once on the wire, but
                        // we share the pool across connections so explicit clear keeps the
                        // pool bucket free of stale content.
                        Array.Clear(encRented, 0, encLen);
                        ArrayPool<byte>.Shared.Return(encRented);
                    }
                }
                finally
                {
                    // Wipe the plaintext we just encrypted before handing the buffer back.
                    Array.Clear(innerRented, 0, innerLen);
                    ArrayPool<byte>.Shared.Return(innerRented);
                }
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
                int chunkLen = Math.Min(data.Length - offset, MaxSendPlaintext);
                byte[] header = BuildHeader(type, (ushort)chunkLen);

                _stream.Write(header);
                _stream.Write(data.Slice(offset, chunkLen));
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

        if (_readCipher != null && outerType == ContentType.ApplicationData)
        {
            byte[] encRented = ArrayPool<byte>.Shared.Rent(length);
            int ctLen = length - _readCipher.TagLength;
            if (ctLen < 0)
            {
                ArrayPool<byte>.Shared.Return(encRented);
                return null;
            }
            byte[] ptRented = ArrayPool<byte>.Shared.Rent(ctLen);
            try
            {
                BinaryHelper.ReadExactInto(_stream, encRented.AsSpan(0, length));
                if (!_readCipher.TryDecryptInto(
                    new ReadOnlySpan<byte>(encRented, 0, length), header,
                    ptRented.AsSpan(0, ctLen)))
                    return null;

                int end = ctLen - 1;
                while (end >= 0 && ptRented[end] == 0) end--;
                if (end < 0) return null;

                byte rawType = ptRented[end];
                if (rawType != (byte)ContentType.ChangeCipherSpec && rawType != (byte)ContentType.Alert
                    && rawType != (byte)ContentType.Handshake && rawType != (byte)ContentType.ApplicationData)
                    return null; // invalid inner content type — treat as failed trial decryption

                byte[] payload = new byte[end];
                new ReadOnlySpan<byte>(ptRented, 0, end).CopyTo(payload);
                return ((ContentType)rawType, payload);
            }
            finally
            {
                Array.Clear(encRented, 0, length);
                ArrayPool<byte>.Shared.Return(encRented);
                Array.Clear(ptRented, 0, ctLen);
                ArrayPool<byte>.Shared.Return(ptRented);
            }
        }

        byte[] plain = BinaryHelper.ReadExact(_stream, length);
        return (outerType, plain);
    }

    /// <summary>Async version of TryReadRecord for trial decryption.</summary>
    public async Task<(ContentType type, byte[] payload)?> TryReadRecordAsync(CancellationToken ct = default)
    {
        byte[] header = await BinaryHelper.ReadExactAsync(_stream, 5, ct).ConfigureAwait(false);
        var outerType = (ContentType)header[0];
        ushort length = BinaryHelper.ReadUInt16(header.AsSpan(3));

        if (length > TlsConst.MaxCiphertextLength)
            throw new TlsException(AlertDescription.RecordOverflow, $"Record too large: {length}");

        if (_readCipher != null && outerType == ContentType.ApplicationData)
        {
            byte[] encRented = ArrayPool<byte>.Shared.Rent(length);
            int ctLen = length - _readCipher.TagLength;
            if (ctLen < 0)
            {
                ArrayPool<byte>.Shared.Return(encRented);
                return null;
            }
            byte[] ptRented = ArrayPool<byte>.Shared.Rent(ctLen);
            try
            {
                await BinaryHelper.ReadExactIntoAsync(_stream, encRented.AsMemory(0, length), ct).ConfigureAwait(false);
                if (!_readCipher.TryDecryptInto(
                    new ReadOnlySpan<byte>(encRented, 0, length), header,
                    ptRented.AsSpan(0, ctLen)))
                    return null;

                int end = ctLen - 1;
                while (end >= 0 && ptRented[end] == 0) end--;
                if (end < 0) return null;

                byte rawType = ptRented[end];
                if (rawType != (byte)ContentType.ChangeCipherSpec && rawType != (byte)ContentType.Alert
                    && rawType != (byte)ContentType.Handshake && rawType != (byte)ContentType.ApplicationData)
                    return null;

                byte[] payload = new byte[end];
                new ReadOnlySpan<byte>(ptRented, 0, end).CopyTo(payload);
                return ((ContentType)rawType, payload);
            }
            finally
            {
                Array.Clear(encRented, 0, length);
                ArrayPool<byte>.Shared.Return(encRented);
                Array.Clear(ptRented, 0, ctLen);
                ArrayPool<byte>.Shared.Return(ptRented);
            }
        }

        byte[] plain = await BinaryHelper.ReadExactAsync(_stream, length, ct).ConfigureAwait(false);
        return (outerType, plain);
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

        if (_readCipher != null && outerType == ContentType.ApplicationData)
        {
            int ctLen = length - _readCipher.TagLength;
            // RFC 8446 §5.2: reject records too short to hold the AEAD tag with bad_record_mac
            // instead of throwing a raw ArgumentOutOfRangeException from ArrayPool.Rent below.
            if (ctLen < 0)
                throw new TlsException(AlertDescription.BadRecordMac, "Record too short for AEAD tag");
            byte[] encRented = ArrayPool<byte>.Shared.Rent(length);
            byte[] ptRented = ArrayPool<byte>.Shared.Rent(ctLen);
            try
            {
                await BinaryHelper.ReadExactIntoAsync(_stream, encRented.AsMemory(0, length), ct).ConfigureAwait(false);
                _readCipher.DecryptInto(
                    new ReadOnlySpan<byte>(encRented, 0, length),
                    header,
                    ptRented.AsSpan(0, ctLen));

                int end = ctLen - 1;
                while (end >= 0 && ptRented[end] == 0) end--;
                if (end < 0)
                    throw new TlsException(AlertDescription.UnexpectedMessage, "Empty inner plaintext");

                byte rawType = ptRented[end];
                if (rawType != (byte)ContentType.ChangeCipherSpec && rawType != (byte)ContentType.Alert
                    && rawType != (byte)ContentType.Handshake && rawType != (byte)ContentType.ApplicationData)
                    throw new TlsException(AlertDescription.UnexpectedMessage, $"Invalid inner content type: {rawType}");

                byte[] payload = new byte[end];
                new ReadOnlySpan<byte>(ptRented, 0, end).CopyTo(payload);
                return ((ContentType)rawType, payload);
            }
            finally
            {
                Array.Clear(encRented, 0, length);
                ArrayPool<byte>.Shared.Return(encRented);
                Array.Clear(ptRented, 0, ctLen);
                ArrayPool<byte>.Shared.Return(ptRented);
            }
        }

        byte[] plain = await BinaryHelper.ReadExactAsync(_stream, length, ct).ConfigureAwait(false);
        return (outerType, plain);
    }

    /// <summary>Write one TLS record asynchronously, encrypting if a write cipher is active.
    /// <c>data</c> is a Memory so callers can pass a slice without first materialising a
    /// fresh <c>byte[]</c>. Span isn't usable here because spans can't cross await boundaries.</summary>
    public async Task WriteRecordAsync(ContentType type, ReadOnlyMemory<byte> data, CancellationToken ct = default)
    {
        if (_writeCipher != null)
        {
            // Fragment to respect RFC 8446 Section 5.1 record size limits
            int offset = 0;
            while (offset < data.Length)
            {
                int chunkLen = Math.Min(data.Length - offset, MaxSendPlaintext);

                int innerLen = chunkLen + 1; // +1 for content type
                if (PaddingBlockSize > 0)
                    innerLen = ((innerLen + PaddingBlockSize - 1) / PaddingBlockSize) * PaddingBlockSize;

                // Mirror the sync path: pool BOTH the plaintext slot and the ciphertext
                // slot. The encrypted buffer must live across the awaits; ArrayPool
                // buffers are safe across awaits (just byte[] references), so we keep
                // it rented for the whole send and return at the finally.
                byte[] innerRented = ArrayPool<byte>.Shared.Rent(innerLen);
                int encLen = innerLen + _writeCipher.TagLength;
                byte[] encRented = ArrayPool<byte>.Shared.Rent(encLen);
                byte[] header;
                try
                {
                    data.Span.Slice(offset, chunkLen).CopyTo(innerRented);
                    innerRented[chunkLen] = (byte)type;
                    if (innerLen > chunkLen + 1)
                        Array.Clear(innerRented, chunkLen + 1, innerLen - chunkLen - 1);

                    header = BuildHeader(ContentType.ApplicationData, (ushort)encLen);

                    _writeCipher.EncryptInto(
                        new ReadOnlySpan<byte>(innerRented, 0, innerLen),
                        header,
                        encRented.AsSpan(0, encLen));

                    // Plaintext is encrypted now; wipe + return early so the inner pool
                    // bucket can be reused while the wire write is in flight.
                    Array.Clear(innerRented, 0, innerLen);
                    ArrayPool<byte>.Shared.Return(innerRented);
                    innerRented = null!; // mark consumed so finally doesn't double-return

                    await _stream.WriteAsync(header, ct).ConfigureAwait(false);
                    await _stream.WriteAsync(encRented.AsMemory(0, encLen), ct).ConfigureAwait(false);
                }
                finally
                {
                    if (innerRented != null)
                    {
                        Array.Clear(innerRented, 0, innerLen);
                        ArrayPool<byte>.Shared.Return(innerRented);
                    }
                    Array.Clear(encRented, 0, encLen);
                    ArrayPool<byte>.Shared.Return(encRented);
                }
                offset += chunkLen;
            }
            await _stream.FlushAsync(ct).ConfigureAwait(false);
        }
        else
        {
            int offset = 0;
            while (offset < data.Length)
            {
                int chunkLen = Math.Min(data.Length - offset, MaxSendPlaintext);
                byte[] header = BuildHeader(type, (ushort)chunkLen);

                await _stream.WriteAsync(header, ct).ConfigureAwait(false);
                await _stream.WriteAsync(data.Slice(offset, chunkLen), ct).ConfigureAwait(false);
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
