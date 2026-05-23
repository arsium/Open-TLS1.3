#nullable disable
#pragma warning disable IL3050, IL2070, IL2026, IL2057, IL2059, IL2067, IL2072, IL2075, IL2080, IL2087, IL2090, IL2091, IL3051, CS3021, SYSLIB0051, CA1857, CS0105, CS1591, CA2014, CS8500

using Org.BouncyCastle.Math;

namespace Org.BouncyCastle.Asn1.X509
{
    /**
     * The CRLNumber object.
     * <pre>
     * CRLNumber::= Integer(0..MAX)
     * </pre>
     */
    public class CrlNumber
        : DerInteger
    {
        public CrlNumber(
			BigInteger number)
			: base(number)
        {
        }

		public BigInteger Number
		{
			get { return PositiveValue; }
		}

		public override string ToString()
		{
			return "CRLNumber: " + Number;
		}
	}
}
