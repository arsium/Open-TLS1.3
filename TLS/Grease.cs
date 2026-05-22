namespace TLS;

/// <summary>
/// GREASE reserved values (RFC 8701). A client advertises these dummy values so peers don't
/// ossify on the set of known values; a compliant peer MUST ignore them. We use fixed values
/// (RFC 8701 permits this) so they never perturb the PSK-binder transcript.
/// </summary>
internal static class Grease
{
    // All 16 GREASE values have the form 0x?A?A with both bytes equal: 0x0A0A, 0x1A1A, ... 0xFAFA.
    public const ushort CipherSuite = 0x0A0A;
    public const ushort Group = 0x1A1A;
    public const ushort SignatureAlgorithm = 0x2A2A;
    public const ushort Version = 0x3A3A;
    public const ushort Extension = 0x4A4A;

    /// <summary>True if a 16-bit value is a reserved GREASE value (both bytes equal and low nibble 0xA).</summary>
    public static bool Is(ushort value) =>
        (value & 0x0F0F) == 0x0A0A && (value >> 8) == (value & 0xFF);
}
