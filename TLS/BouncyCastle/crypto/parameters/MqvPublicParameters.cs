#nullable disable
#pragma warning disable IL3050, IL2070, IL2026, IL2057, IL2059, IL2067, IL2072, IL2075, IL2080, IL2087, IL2090, IL2091, IL3051, CS3021, SYSLIB0051, CA1857, CS0105, CS1591, CA2014, CS8500

using System;

namespace Org.BouncyCastle.Crypto.Parameters
{
    public class MqvPublicParameters
        : ICipherParameters
    {
        private readonly ECPublicKeyParameters m_staticPublicKey;
        private readonly ECPublicKeyParameters m_ephemeralPublicKey;

        public MqvPublicParameters(ECPublicKeyParameters staticPublicKey, ECPublicKeyParameters ephemeralPublicKey)
        {
            m_staticPublicKey = staticPublicKey ?? throw new ArgumentNullException(nameof(staticPublicKey));
            m_ephemeralPublicKey = ephemeralPublicKey ?? throw new ArgumentNullException(nameof(ephemeralPublicKey));

            if (!staticPublicKey.Parameters.Equals(ephemeralPublicKey.Parameters))
                throw new ArgumentException("Static and ephemeral public keys have different domain parameters");
        }

        public virtual ECPublicKeyParameters EphemeralPublicKey => m_ephemeralPublicKey;

        public virtual ECPublicKeyParameters StaticPublicKey => m_staticPublicKey;
    }
}
