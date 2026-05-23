#nullable disable
#pragma warning disable IL3050, IL2070, IL2026, IL2057, IL2059, IL2067, IL2072, IL2075, IL2080, IL2087, IL2090, IL2091, IL3051, CS3021, SYSLIB0051, CA1857, CS0105, CS1591, CA2014, CS8500

using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Macs;

namespace Org.BouncyCastle.Crypto.Modes
{
    /// <summary>
    /// Implementation of the XChaCha20-Poly1305 AEAD construction as defined in
    /// draft-irtf-cfrg-xchacha. Identical to ChaCha20-Poly1305 (RFC 8439) but using
    /// XChaCha20 with a 192-bit nonce in place of ChaCha20.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The 24-byte (192-bit) nonce permits safe random-nonce selection, which is impractical with
    /// the 96-bit nonce of ChaCha20-Poly1305.
    /// </para>
    /// </remarks>
    public class XChaCha20Poly1305
        : ChaCha20Poly1305
    {
        /// <summary>Default constructor using the standard <see cref="Poly1305"/> MAC.</summary>
        public XChaCha20Poly1305()
            : this(new Poly1305())
        {
        }

        /// <summary>Constructor allowing a custom Poly1305 implementation.</summary>
        public XChaCha20Poly1305(IMac poly1305)
            : base(new XChaCha20Engine(), poly1305, 24)
        {
        }

        /// <summary>The name of the algorithm ("XChaCha20Poly1305").</summary>
        public override string AlgorithmName => "XChaCha20Poly1305";
    }
}
