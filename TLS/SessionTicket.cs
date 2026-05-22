namespace TLS;

using System.Security.Cryptography;

/// <summary>Represents a stored TLS 1.3 session ticket for resumption.</summary>
public sealed class SessionTicket
{
    public byte[] Ticket { get; init; } = null!;
    public byte[] ResumptionSecret { get; init; } = null!;
    public CipherSuite CipherSuite { get; init; }
    public DateTime IssuedAt { get; init; }
    public uint LifetimeSeconds { get; init; }
    public uint AgeAdd { get; init; }
    public uint MaxEarlyDataSize { get; init; }
    public string? ServerName { get; init; }
}

/// <summary>Client-side session ticket store for PSK resumption.</summary>
public sealed class SessionTicketStore
{
    private readonly Dictionary<string, List<SessionTicket>> _tickets = new();

    public void Add(string serverName, SessionTicket ticket)
    {
        lock (_tickets)
        {
            if (!_tickets.TryGetValue(serverName, out var list))
            {
                list = new List<SessionTicket>();
                _tickets[serverName] = list;
            }
            list.Add(ticket);
        }
    }

    /// <summary>Get a valid ticket for the given server (removes expired ones).</summary>
    public SessionTicket? Get(string serverName)
    {
        lock (_tickets)
        {
            if (!_tickets.TryGetValue(serverName, out var list)) return null;

            var now = DateTime.UtcNow;
            list.RemoveAll(t => now > t.IssuedAt.AddSeconds(t.LifetimeSeconds));

            if (list.Count == 0)
            {
                _tickets.Remove(serverName);
                return null;
            }

            // Return and remove the first valid ticket (single-use)
            var ticket = list[0];
            list.RemoveAt(0);
            if (list.Count == 0) _tickets.Remove(serverName);
            return ticket;
        }
    }
}

/// <summary>Server-side ticket encryption/decryption using AES-256-GCM, with 0-RTT anti-replay and key rotation.</summary>
public sealed class TicketEncryption
{
    private sealed class KeyEntry
    {
        public uint KeyId { get; init; }
        public byte[] Key { get; init; } = null!;
        public DateTime CreatedAt { get; init; }
    }

    private readonly List<KeyEntry> _keys = new();
    private readonly object _keyLock = new();
    private uint _nextKeyId;

    // Anti-replay: track used ticket hashes for 0-RTT single-use enforcement (RFC 8446 §8)
    private readonly Dictionary<string, DateTime> _usedTickets = new();
    private DateTime _lastCleanup = DateTime.UtcNow;

    public TicketEncryption(byte[]? key = null)
    {
        byte[] k = key ?? RandomnessWrapper.GetKeyBytes(32);
        _keys.Add(new KeyEntry { KeyId = 0, Key = k, CreatedAt = DateTime.UtcNow });
        _nextKeyId = 1;
    }

    /// <summary>Generate a new encryption key. Old keys are retained for decrypting existing tickets.</summary>
    public void RotateKey(byte[]? newKey = null)
    {
        lock (_keyLock)
        {
            byte[] k = newKey ?? RandomnessWrapper.GetKeyBytes(32);
            _keys.Add(new KeyEntry { KeyId = _nextKeyId++, Key = k, CreatedAt = DateTime.UtcNow });
        }
    }

    /// <summary>Remove keys older than the given duration. The current (newest) key is never removed.</summary>
    public void PurgeOldKeys(TimeSpan maxAge)
    {
        lock (_keyLock)
        {
            if (_keys.Count <= 1) return;
            var cutoff = DateTime.UtcNow - maxAge;
            var current = _keys[^1];
            _keys.RemoveAll(k => k.CreatedAt < cutoff && k != current);
        }
    }

    /// <summary>
    /// Mark a ticket as used for 0-RTT. Returns true if this is the first use (safe),
    /// false if the ticket was already used (replay detected).
    /// </summary>
    public bool TryMarkUsedForEarlyData(byte[] ticketBlob)
    {
        string key = Convert.ToHexString(SHA256.HashData(ticketBlob));
        lock (_usedTickets)
        {
            CleanupExpired();
            if (_usedTickets.ContainsKey(key)) return false; // replay!
            _usedTickets[key] = DateTime.UtcNow;
            return true;
        }
    }

    private void CleanupExpired()
    {
        if (DateTime.UtcNow - _lastCleanup < TimeSpan.FromMinutes(5)) return;
        var cutoff = DateTime.UtcNow.AddDays(-7);
        var expired = new List<string>();
        foreach (var kv in _usedTickets)
            if (kv.Value < cutoff) expired.Add(kv.Key);
        foreach (var k in expired) _usedTickets.Remove(k);
        _lastCleanup = DateTime.UtcNow;
    }

    /// <summary>Seal ticket plaintext into an encrypted blob: keyId(4) || IV(12) || ciphertext || tag(16).</summary>
    public byte[] Seal(byte[] plaintext)
    {
        KeyEntry current;
        lock (_keyLock) { current = _keys[^1]; }

        byte[] iv = RandomnessWrapper.GetBytes(12);
        byte[] ciphertext = new byte[plaintext.Length];
        byte[] tag = new byte[16];

        using var aes = new AesGcm(current.Key, 16);
        aes.Encrypt(iv, plaintext, ciphertext, tag);

        byte[] result = new byte[4 + 12 + ciphertext.Length + 16];
        result[0] = (byte)(current.KeyId >> 24);
        result[1] = (byte)(current.KeyId >> 16);
        result[2] = (byte)(current.KeyId >> 8);
        result[3] = (byte)current.KeyId;
        Buffer.BlockCopy(iv, 0, result, 4, 12);
        Buffer.BlockCopy(ciphertext, 0, result, 16, ciphertext.Length);
        Buffer.BlockCopy(tag, 0, result, 16 + ciphertext.Length, 16);
        return result;
    }

    /// <summary>Open an encrypted ticket blob. Returns null if decryption fails or key was rotated away.</summary>
    public byte[]? Open(byte[] blob)
    {
        if (blob.Length < 4 + 12 + 16) return null;

        uint keyId = BinaryHelper.ReadUInt32(blob.AsSpan(0));
        KeyEntry? entry;
        lock (_keyLock) { entry = _keys.Find(k => k.KeyId == keyId); }
        if (entry == null) return null;

        byte[] iv = blob[4..16];
        byte[] ciphertext = blob[16..^16];
        byte[] tag = blob[^16..];
        byte[] plaintext = new byte[ciphertext.Length];

        try
        {
            using var aes = new AesGcm(entry.Key, 16);
            aes.Decrypt(iv, ciphertext, tag, plaintext);
            return plaintext;
        }
        catch (CryptographicException)
        {
            return null;
        }
    }

    /// <summary>Encode session state into ticket plaintext.</summary>
    public static byte[] EncodeTicketState(byte[] resumptionSecret, CipherSuite suite,
        uint ageAdd, DateTime issuedAt, uint maxEarlyData)
    {
        using var ms = new MemoryStream();
        // resumption_secret (length-prefixed)
        BinaryHelper.WriteUInt16(ms, (ushort)resumptionSecret.Length);
        ms.Write(resumptionSecret);
        // cipher_suite
        BinaryHelper.WriteUInt16(ms, (ushort)suite);
        // age_add
        BinaryHelper.WriteUInt32(ms, ageAdd);
        // creation_timestamp (unix seconds)
        long unix = new DateTimeOffset(issuedAt).ToUnixTimeSeconds();
        BinaryHelper.WriteUInt32(ms, (uint)(unix >> 32));
        BinaryHelper.WriteUInt32(ms, (uint)unix);
        // max_early_data
        BinaryHelper.WriteUInt32(ms, maxEarlyData);
        return ms.ToArray();
    }

    /// <summary>Decode ticket state from plaintext.</summary>
    public static (byte[] resumptionSecret, CipherSuite suite, uint ageAdd, DateTime issuedAt, uint maxEarlyData)?
        DecodeTicketState(byte[] plaintext)
    {
        try
        {
            int pos = 0;
            ushort secretLen = BinaryHelper.ReadUInt16(plaintext.AsSpan(pos)); pos += 2;
            byte[] secret = plaintext[pos..(pos + secretLen)]; pos += secretLen;
            var suite = (CipherSuite)BinaryHelper.ReadUInt16(plaintext.AsSpan(pos)); pos += 2;
            uint ageAdd = BinaryHelper.ReadUInt32(plaintext.AsSpan(pos)); pos += 4;
            uint hi = BinaryHelper.ReadUInt32(plaintext.AsSpan(pos)); pos += 4;
            uint lo = BinaryHelper.ReadUInt32(plaintext.AsSpan(pos)); pos += 4;
            long unix = ((long)hi << 32) | lo;
            var issuedAt = DateTimeOffset.FromUnixTimeSeconds(unix).UtcDateTime;
            uint maxEarly = BinaryHelper.ReadUInt32(plaintext.AsSpan(pos));
            return (secret, suite, ageAdd, issuedAt, maxEarly);
        }
        catch
        {
            return null;
        }
    }
}
