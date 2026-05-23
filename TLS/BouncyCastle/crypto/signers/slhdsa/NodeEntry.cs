#nullable disable
#pragma warning disable IL3050, IL2070, IL2026, IL2057, IL2059, IL2067, IL2072, IL2075, IL2080, IL2087, IL2090, IL2091, IL3051, CS3021, SYSLIB0051, CA1857, CS0105, CS1591, CA2014, CS8500

namespace Org.BouncyCastle.Crypto.Signers.SlhDsa
{
    internal sealed class NodeEntry
    {
        private readonly byte[] m_nodeValue;
        private readonly uint m_nodeHeight;

        internal NodeEntry(byte[] nodeValue, uint nodeHeight)
        {
            m_nodeValue = nodeValue;
            m_nodeHeight = nodeHeight;
        }

        internal uint NodeHeight => m_nodeHeight;

        internal byte[] NodeValue => m_nodeValue;
    }
}
