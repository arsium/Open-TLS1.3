#nullable disable
#pragma warning disable IL3050, IL2070, IL2026, IL2057, IL2059, IL2067, IL2072, IL2075, IL2080, IL2087, IL2090, IL2091, IL3051, CS3021, SYSLIB0051, CA1857, CS0105, CS1591, CA2014, CS8500

namespace Org.BouncyCastle.Crypto.Generators
{
	/**
	 * KFD1 generator for derived keys and ivs as defined by IEEE P1363a/ISO 18033
	 * <br/>
	 * This implementation is based on IEEE P1363/ISO 18033.
	 */
	public sealed class Kdf1BytesGenerator
		: BaseKdfBytesGenerator
	{
		/**
		 * Construct a KDF1 byte generator.
		 *
		 * @param digest the digest to be used as the source of derived keys.
		 */
		public Kdf1BytesGenerator(IDigest digest)
			: base(0, digest)
		{
		}
	}
}
