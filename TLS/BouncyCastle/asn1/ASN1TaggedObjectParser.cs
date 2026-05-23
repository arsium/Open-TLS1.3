#nullable disable
#pragma warning disable IL3050, IL2070, IL2026, IL2057, IL2059, IL2067, IL2072, IL2075, IL2080, IL2087, IL2090, IL2091, IL3051, CS3021, SYSLIB0051, CA1857, CS0105, CS1591, CA2014, CS8500

using System.IO;

namespace Org.BouncyCastle.Asn1
{
    public interface Asn1TaggedObjectParser
        : IAsn1Convertible
    {
        int TagClass { get; }

        int TagNo { get; }

        // TODO[api]
        //bool HasContextTag();

        bool HasContextTag(int tagNo);

        bool HasTag(int tagClass, int tagNo);

        // TODO[api]
        //bool HasTagClass(int tagClass);

        /// <exception cref="IOException"/>
        IAsn1Convertible ParseBaseUniversal(bool declaredExplicit, int baseTagNo);

        /// <summary>Needed for open types, until we have better type-guided parsing support.</summary>
        /// <remarks>
        /// Use sparingly for other purposes, and prefer <see cref="ParseExplicitBaseTagged"/> or
        /// <see cref="ParseBaseUniversal(bool, int)"/> where possible. Before using, check for matching tag
        /// <see cref="TagClass">class</see> and <see cref="TagNo">number</see>.
        /// </remarks>
        /// <exception cref="IOException"/>
        IAsn1Convertible ParseExplicitBaseObject();

        /// <exception cref="IOException"/>
        Asn1TaggedObjectParser ParseExplicitBaseTagged();

        /// <exception cref="IOException"/>
        Asn1TaggedObjectParser ParseImplicitBaseTagged(int baseTagClass, int baseTagNo);
    }
}
