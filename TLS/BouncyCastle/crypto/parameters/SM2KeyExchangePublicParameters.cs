#nullable disable
#pragma warning disable IL3050, IL2070, IL2026, IL2057, IL2059, IL2067, IL2072, IL2075, IL2080, IL2087, IL2090, IL2091, IL3051, CS3021, SYSLIB0051, CA1857, CS0105, CS1591, CA2014, CS8500

﻿using System;

using Org.BouncyCastle.Math.EC;

namespace Org.BouncyCastle.Crypto.Parameters
{
    /// <summary>Public parameters for an SM2 key exchange.</summary>
    /// <remarks>In this case the ephemeralPublicKey provides the random point used in the algorithm.</remarks>
    public class SM2KeyExchangePublicParameters
        : ICipherParameters
    {
        private readonly ECPublicKeyParameters mStaticPublicKey;
        private readonly ECPublicKeyParameters mEphemeralPublicKey;

        public SM2KeyExchangePublicParameters(
            ECPublicKeyParameters staticPublicKey,
            ECPublicKeyParameters ephemeralPublicKey)
        {
            if (staticPublicKey == null)
                throw new ArgumentNullException("staticPublicKey");
            if (ephemeralPublicKey == null)
                throw new ArgumentNullException("ephemeralPublicKey");
            if (!staticPublicKey.Parameters.Equals(ephemeralPublicKey.Parameters))
                throw new ArgumentException("Static and ephemeral public keys have different domain parameters");

            this.mStaticPublicKey = staticPublicKey;
            this.mEphemeralPublicKey = ephemeralPublicKey;
        }

        public virtual ECPublicKeyParameters StaticPublicKey
        {
            get { return mStaticPublicKey; }
        }

        public virtual ECPublicKeyParameters EphemeralPublicKey
        {
            get { return mEphemeralPublicKey; }
        }
    }
}
