#nullable disable
#pragma warning disable IL3050, IL2070, IL2026, IL2057, IL2059, IL2067, IL2072, IL2075, IL2080, IL2087, IL2090, IL2091, IL3051, CS3021, SYSLIB0051, CA1857, CS0105, CS1591, CA2014, CS8500

namespace Org.BouncyCastle.Crypto.Engines
{
	/// <remarks>
	/// An implementation of the Camellia key wrapper based on RFC 3657/RFC 3394.
	/// <p/>
	/// For further details see: <a href="http://www.ietf.org/rfc/rfc3657.txt">http://www.ietf.org/rfc/rfc3657.txt</a>.
	/// </remarks>
	public class CamelliaWrapEngine
		: Rfc3394WrapEngine
	{
		public CamelliaWrapEngine()
			: base(new CamelliaEngine())
		{
		}
	}
}
