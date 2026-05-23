#nullable disable
#pragma warning disable IL3050, IL2070, IL2026, IL2057, IL2059, IL2067, IL2072, IL2075, IL2080, IL2087, IL2090, IL2091, IL3051, CS3021, SYSLIB0051, CA1857, CS0105, CS1591, CA2014, CS8500

using System;

namespace Org.BouncyCastle.Asn1
{
    public class DerGeneralizedTime
        : Asn1GeneralizedTime
    {
        public DerGeneralizedTime(string timeString)
            : base(timeString)
        {
        }

        public DerGeneralizedTime(DateTime dateTime)
            : base(dateTime)
        {
        }

        internal DerGeneralizedTime(byte[] contents)
            : base(contents)
        {
        }

        internal override IAsn1Encoding GetEncoding(int encoding)
        {
            return new PrimitiveEncoding(Asn1Tags.Universal, Asn1Tags.GeneralizedTime,
                GetContents(Asn1OutputStream.EncodingDer));
        }

        internal override IAsn1Encoding GetEncodingImplicit(int encoding, int tagClass, int tagNo)
        {
            return new PrimitiveEncoding(tagClass, tagNo, GetContents(Asn1OutputStream.EncodingDer));
        }
    }
}
