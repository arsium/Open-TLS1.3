#nullable disable
#pragma warning disable IL3050, IL2070, IL2026, IL2057, IL2059, IL2067, IL2072, IL2075, IL2080, IL2087, IL2090, IL2091, IL3051, CS3021, SYSLIB0051, CA1857, CS0105, CS1591, CA2014, CS8500

namespace Org.BouncyCastle.Crypto
{
    public abstract class AsymmetricKeyParameter
        : ICipherParameters
    {
        private readonly bool m_privateKey;

        protected AsymmetricKeyParameter(bool privateKey)
        {
            m_privateKey = privateKey;
        }

        public bool IsPrivate => m_privateKey;

        public override bool Equals(object obj) => obj is AsymmetricKeyParameter that && Equals(that);

        protected bool Equals(AsymmetricKeyParameter other) => m_privateKey == other.m_privateKey;

        public override int GetHashCode() => m_privateKey.GetHashCode();
    }
}
