#nullable disable
#pragma warning disable IL3050, IL2070, IL2026, IL2057, IL2059, IL2067, IL2072, IL2075, IL2080, IL2087, IL2090, IL2091, IL3051, CS3021, SYSLIB0051, CA1857, CS0105, CS1591, CA2014, CS8500

namespace Org.BouncyCastle.Asn1.Smime
{
    /**
     * Handler for creating a vector S/MIME Capabilities
     */
    public class SmimeCapabilityVector
    {
        private readonly Asn1EncodableVector m_capabilities = new Asn1EncodableVector();

        public void AddCapability(DerObjectIdentifier capability) =>
            m_capabilities.Add(DerSequence.FromElement(capability));

        public void AddCapability(DerObjectIdentifier capability, int value) =>
            AddCapability(capability, DerInteger.ValueOf(value));

        public void AddCapability(DerObjectIdentifier capability, Asn1Encodable parameters) =>
            m_capabilities.Add(DerSequence.FromElements(capability, parameters));

        public Asn1EncodableVector ToAsn1EncodableVector() => m_capabilities;
    }
}
