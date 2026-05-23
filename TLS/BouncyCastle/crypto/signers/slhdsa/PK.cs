#nullable disable
#pragma warning disable IL3050, IL2070, IL2026, IL2057, IL2059, IL2067, IL2072, IL2075, IL2080, IL2087, IL2090, IL2091, IL3051, CS3021, SYSLIB0051, CA1857, CS0105, CS1591, CA2014, CS8500

namespace Org.BouncyCastle.Crypto.Signers.SlhDsa
{
    internal sealed class PK
    {
        private readonly byte[] m_seed;
        private readonly byte[] m_root;

        internal PK(byte[] seed, byte[] root)
        {
            m_seed = seed;
            m_root = root;
        }

        internal byte[] Root => m_root;

        internal byte[] Seed => m_seed;
    }
}
