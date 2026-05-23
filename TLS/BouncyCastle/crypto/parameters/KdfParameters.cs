#nullable disable
#pragma warning disable IL3050, IL2070, IL2026, IL2057, IL2059, IL2067, IL2072, IL2075, IL2080, IL2087, IL2090, IL2091, IL3051, CS3021, SYSLIB0051, CA1857, CS0105, CS1591, CA2014, CS8500

namespace Org.BouncyCastle.Crypto.Parameters
{
    /// <summary>Parameters for Key Derivation Functions for IEEE P1363a.</summary>
    public class KdfParameters
        : IDerivationParameters
    {
        private readonly byte[] m_iv;
        private readonly byte[] m_shared;

        public KdfParameters(byte[] shared, byte[] iv)
        {
            m_shared = shared;
            m_iv = iv;
        }

        public byte[] GetIV() => m_iv;

        public byte[] GetSharedSecret() => m_shared;
    }
}
