#nullable disable
#pragma warning disable IL3050, IL2070, IL2026, IL2057, IL2059, IL2067, IL2072, IL2075, IL2080, IL2087, IL2090, IL2091, IL3051, CS3021, SYSLIB0051, CA1857, CS0105, CS1591, CA2014, CS8500

namespace Org.BouncyCastle.Crypto.Engines
{
    /// <remarks>
    /// An implementation of the AES Key Wrapper from the NIST Key Wrap Specification.
    /// <p/>
    /// For further details see: <a href="http://csrc.nist.gov/encryption/kms/key-wrap.pdf">http://csrc.nist.gov/encryption/kms/key-wrap.pdf</a>.
    /// </remarks>
    public class AesWrapEngine
		: Rfc3394WrapEngine
	{
        /// <summary>
        /// Create a regular AesWrapEngine specifying the encrypt for wrapping, decrypt for unwrapping.
        /// </summary>
        public AesWrapEngine()
			: base(AesUtilities.CreateEngine())
		{
		}

        /// <summary>
        /// Create an AESWrapEngine where the underlying cipher is (optionally) set to decrypt for wrapping, encrypt for
        /// unwrapping.
        /// </summary>
        /// <param name="useReverseDirection">true if underlying cipher should be used in decryption mode, false
        /// otherwise.</param>
        public AesWrapEngine(bool useReverseDirection)
            : base(AesUtilities.CreateEngine(), useReverseDirection)
        {
        }
    }
}
