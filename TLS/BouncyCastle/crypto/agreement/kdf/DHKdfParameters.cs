#nullable disable
#pragma warning disable IL3050, IL2070, IL2026, IL2057, IL2059, IL2067, IL2072, IL2075, IL2080, IL2087, IL2090, IL2091, IL3051, CS3021, SYSLIB0051, CA1857, CS0105, CS1591, CA2014, CS8500

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto.Agreement.Kdf
{
    public class DHKdfParameters
        : IDerivationParameters
    {
        private readonly DerObjectIdentifier m_algorithm;
        private readonly int m_keySize;
        private readonly byte[] m_z;
        private readonly byte[] m_extraInfo;

        public DHKdfParameters(DerObjectIdentifier algorithm, int keySize, byte[] z)
            : this(algorithm, keySize, z, null)
        {
        }

        public DHKdfParameters(DerObjectIdentifier algorithm, int keySize, byte[] z, byte[] extraInfo)
        {
            m_algorithm = algorithm;
            m_keySize = keySize;
            m_z = Arrays.CopyBuffer(z);
            m_extraInfo = Arrays.Clone(extraInfo);
        }

        public DerObjectIdentifier Algorithm => m_algorithm;

        internal byte[] ExtraInfo => m_extraInfo;

        public byte[] GetZ() => Arrays.CopyBuffer(m_z);

        public byte[] GetExtraInfo() => Arrays.Clone(m_extraInfo);

        public int KeySize => m_keySize;

        internal byte[] Z => m_z;
    }
}
