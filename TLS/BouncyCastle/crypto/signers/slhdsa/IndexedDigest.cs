#nullable disable
#pragma warning disable IL3050, IL2070, IL2026, IL2057, IL2059, IL2067, IL2072, IL2075, IL2080, IL2087, IL2090, IL2091, IL3051, CS3021, SYSLIB0051, CA1857, CS0105, CS1591, CA2014, CS8500

namespace Org.BouncyCastle.Crypto.Signers.SlhDsa
{
    internal sealed class IndexedDigest
    {
        private readonly ulong m_idxTree;
        private readonly uint m_idxLeaf;
        private readonly byte[] m_digest;

        internal IndexedDigest(ulong idxTree, uint idxLeaf, byte[] digest)
        {
            m_idxTree = idxTree;
            m_idxLeaf = idxLeaf;
            m_digest = digest;
        }

        internal byte[] Digest => m_digest;

        internal uint IdxLeaf => m_idxLeaf;

        internal ulong IdxTree => m_idxTree;
    }
}
