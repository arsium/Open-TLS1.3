#nullable disable
#pragma warning disable IL3050, IL2070, IL2026, IL2057, IL2059, IL2067, IL2072, IL2075, IL2080, IL2087, IL2090, IL2091, IL3051, CS3021, SYSLIB0051, CA1857, CS0105, CS1591, CA2014, CS8500

using System;

namespace Org.BouncyCastle.Asn1
{
    /**
     * A Null object.
     */
    // TODO[api] Make sealed
    public class DerNull
        : Asn1Null
    {
        public static readonly DerNull Instance = new DerNull();

        // TODO[api] Make private
        protected internal DerNull()
        {
        }

        internal override IAsn1Encoding GetEncoding(int encoding) =>
            new PrimitiveEncoding(Asn1Tags.Universal, Asn1Tags.Null, Array.Empty<byte>());

        internal override IAsn1Encoding GetEncodingImplicit(int encoding, int tagClass, int tagNo) =>
            new PrimitiveEncoding(tagClass, tagNo, Array.Empty<byte>());

        internal sealed override DerEncoding GetEncodingDer() =>
            new PrimitiveDerEncoding(Asn1Tags.Universal, Asn1Tags.Null, Array.Empty<byte>());

        internal sealed override DerEncoding GetEncodingDerImplicit(int tagClass, int tagNo) =>
            new PrimitiveDerEncoding(tagClass, tagNo, Array.Empty<byte>());

        protected override bool Asn1Equals(Asn1Object asn1Object) => asn1Object is DerNull;

        protected override int Asn1GetHashCode() => -1;
    }
}
