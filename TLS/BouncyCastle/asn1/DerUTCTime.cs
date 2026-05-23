#nullable disable
#pragma warning disable IL3050, IL2070, IL2026, IL2057, IL2059, IL2067, IL2072, IL2075, IL2080, IL2087, IL2090, IL2091, IL3051, CS3021, SYSLIB0051, CA1857, CS0105, CS1591, CA2014, CS8500

using System;

namespace Org.BouncyCastle.Asn1
{
    public class DerUtcTime
        : Asn1UtcTime
    {
        public DerUtcTime(string timeString)
			: base(timeString)
        {
        }

        [Obsolete("Use `DerUtcTime(DateTime, int)' instead")]
        public DerUtcTime(DateTime dateTime)
			: base(dateTime)
        {
        }

        public DerUtcTime(DateTime dateTime, int twoDigitYearMax)
            : base(dateTime, twoDigitYearMax)
        {
        }

        internal DerUtcTime(byte[] contents)
			: base(contents)
        {
        }

        internal override IAsn1Encoding GetEncoding(int encoding)
        {
            return new PrimitiveEncoding(Asn1Tags.Universal, Asn1Tags.UtcTime,
                GetContents(Asn1OutputStream.EncodingDer));
        }

        internal override IAsn1Encoding GetEncodingImplicit(int encoding, int tagClass, int tagNo)
        {
            return new PrimitiveEncoding(tagClass, tagNo, GetContents(Asn1OutputStream.EncodingDer));
        }
    }
}
