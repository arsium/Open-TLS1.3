#nullable disable
#pragma warning disable IL3050, IL2070, IL2026, IL2057, IL2059, IL2067, IL2072, IL2075, IL2080, IL2087, IL2090, IL2091, IL3051, CS3021, SYSLIB0051, CA1857, CS0105, CS1591, CA2014, CS8500


namespace Org.BouncyCastle.Asn1
{
	/**
	 * Marker interface for CHOICE objects - if you implement this in a roll-your-own
	 * object, any attempt to tag the object implicitly will convert the tag to an
	 * explicit one as the encoding rules require.
	 * <p>
	 * If you use this interface your class should also implement the getInstance
	 * pattern which takes a tag object and the tagging mode used. 
	 * </p>
	 */
	// TODO[api] Add method to Report the smallest tag that can appear (for use with CER encoding rules).
	public interface IAsn1Choice
	{
		// marker interface
	}
}
