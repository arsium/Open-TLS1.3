namespace TLS;

using System.Security.Cryptography;

/// <summary>
/// CSPRNG built on RFC 8439 ChaCha20 keystream + fast-key-erasure, seeded from the OS
/// entropy source and reseeded periodically. Drop-in alternative for
/// <see cref="System.Security.Cryptography.RandomNumberGenerator"/> on the hot path —
/// most cryptographic operations need a few bytes of randomness and now hit a managed
/// keystream tap instead of crossing the syscall boundary for every nonce / signature.
///
/// Design (matches BoringSSL's CTR-DRBG construction and Linux's get_random_bytes):
/// <list type="bullet">
///   <item>Seeded once at construction with 32 + 12 bytes from <c>BCryptGenRandom</c>.</item>
///   <item>Reseeded every <see cref="ReseedAfterBytes"/> output bytes; NIST SP 800-90A
///         allows up to 2^48 per CTR-DRBG instance but we reseed orders of magnitude more
///         conservatively to bound the damage window of any single seed compromise.</item>
///   <item><b>Fast key erasure</b>: every <see cref="Fill"/> first reads a fresh 64 bytes
///         of keystream and uses them as the new key + nonce, *before* serving any bytes to
///         the caller. A backward break never reveals past output.</item>
///   <item><b>Fork-safe</b>: detects <c>Environment.ProcessId</c> change between calls
///         (parent forks → child inherits state) and force-reseeds. Cheap PID check on
///         every Fill; matters on Linux, harmless on Windows where fork isn't a thing.</item>
///   <item>Thread-safe via a single lock — TLS server hits this from many connection threads.</item>
/// </list>
///
/// Important: this does NOT remove the BCryptGenRandom / getrandom dependency. It rate-limits
/// it. The OS RNG is still the root of trust for entropy; we just stop hammering it for every
/// 12-byte nonce.
/// </summary>
internal sealed class ChaCha20Drbg : IDisposable
{
    public const int ReseedAfterBytes = 1024 * 1024; // 1 MB; well under NIST's 2^48 ceiling

    private readonly object _lock = new();
    private readonly byte[] _key = new byte[32];
    private readonly byte[] _nonce = new byte[12];
    private long _bytesEmitted;
    private int _seedingPid;
    private bool _disposed;

    public ChaCha20Drbg()
    {
        ReseedFromOs();
    }

    public void Fill(Span<byte> buffer)
    {
        if (buffer.IsEmpty) return;
        lock (_lock)
        {
            EnsureNotDisposed();
            // Fork detection — if PID changed since last seed (Linux fork()), the child
            // inherited our state and would emit the same bytes. Re-seed unconditionally.
            if (Environment.ProcessId != _seedingPid)
                ReseedFromOs();
            // Time-based reseed — bound the damage if any single seed is compromised.
            else if (_bytesEmitted >= ReseedAfterBytes)
                ReseedFromOs();

            // Fast key erasure: first 64 bytes of the new keystream become the next key
            // + nonce, *before* we generate any output for the caller. After this Fill
            // returns, the (key, nonce) pair used for the user's bytes is unrecoverable.
            Span<byte> newKeyMaterial = stackalloc byte[64];
            ChaCha20.Keystream(_key, _nonce, 0, newKeyMaterial);
            // The remaining keystream (from counter 1 onward) is what the user gets.
            ChaCha20.Keystream(_key, _nonce, 1, buffer);
            _bytesEmitted += buffer.Length;

            // Rotate the state to the new key + nonce extracted above.
            newKeyMaterial.Slice(0, 32).CopyTo(_key);
            newKeyMaterial.Slice(32, 12).CopyTo(_nonce);
            CryptographicOperations.ZeroMemory(newKeyMaterial);
        }
    }

    public byte[] GetBytes(int count)
    {
        if (count < 0) throw new ArgumentOutOfRangeException(nameof(count));
        byte[] result = new byte[count];
        Fill(result);
        return result;
    }

    /// <summary>Force an immediate reseed from the OS entropy source.
    /// Useful after long idle periods or on explicit request.</summary>
    public void ForceReseed()
    {
        lock (_lock)
        {
            EnsureNotDisposed();
            ReseedFromOs();
        }
    }

    // Called under _lock. Mixes OS-supplied entropy with the current state so that even a
    // transient bad OS-RNG reading doesn't fully reset us into a known-bad state.
    private void ReseedFromOs()
    {
        Span<byte> osBytes = stackalloc byte[44]; // 32-byte key + 12-byte nonce
        RandomNumberGenerator.Fill(osBytes);

        // XOR the OS entropy into the existing state (defence against OS RNG glitches).
        for (int i = 0; i < 32; i++) _key[i]   ^= osBytes[i];
        for (int i = 0; i < 12; i++) _nonce[i] ^= osBytes[32 + i];

        CryptographicOperations.ZeroMemory(osBytes);
        _bytesEmitted = 0;
        _seedingPid = Environment.ProcessId;
    }

    private void EnsureNotDisposed()
    {
        if (_disposed) throw new ObjectDisposedException(nameof(ChaCha20Drbg));
    }

    public void Dispose()
    {
        lock (_lock)
        {
            if (_disposed) return;
            _disposed = true;
            CryptographicOperations.ZeroMemory(_key);
            CryptographicOperations.ZeroMemory(_nonce);
        }
    }
}
