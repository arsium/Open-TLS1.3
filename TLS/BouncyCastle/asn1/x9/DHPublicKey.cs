#nullable disable
#pragma warning disable IL3050, IL2070, IL2026, IL2057, IL2059, IL2067, IL2072, IL2075, IL2080, IL2087, IL2090, IL2091, IL3051, CS3021, SYSLIB0051, CA1857, CS0105, CS1591, CA2014, CS8500

using System;

namespace Org.BouncyCastle.Asn1.X9
{
    public class DHPublicKey
		: Asn1Encodable
	{
        public static DHPublicKey GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is DHPublicKey dhPublicKey)
                return dhPublicKey;
            return new DHPublicKey(DerInteger.GetInstance(obj));
        }

        public static DHPublicKey GetInstance(Asn1TaggedObject obj, bool isExplicit) =>
            new DHPublicKey(DerInteger.GetInstance(obj, isExplicit));

        public static DHPublicKey GetTagged(Asn1TaggedObject obj, bool isExplicit) =>
            new DHPublicKey(DerInteger.GetTagged(obj, isExplicit));

        private readonly DerInteger m_y;

        public DHPublicKey(DerInteger y)
		{
			m_y = y ?? throw new ArgumentNullException(nameof(y));
        }

        public DerInteger Y => m_y;

        public override Asn1Object ToAsn1Object() => m_y;
	}
}
