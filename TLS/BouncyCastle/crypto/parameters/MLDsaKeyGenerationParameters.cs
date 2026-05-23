#nullable disable
#pragma warning disable IL3050, IL2070, IL2026, IL2057, IL2059, IL2067, IL2072, IL2075, IL2080, IL2087, IL2090, IL2091, IL3051, CS3021, SYSLIB0051, CA1857, CS0105, CS1591, CA2014, CS8500

﻿using System;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Crypto.Parameters
{
    public sealed class MLDsaKeyGenerationParameters
        : KeyGenerationParameters
    {
        private readonly MLDsaParameters m_parameters;

        public MLDsaKeyGenerationParameters(SecureRandom random, MLDsaParameters parameters)
            : base(random, 0)
        {
            m_parameters = parameters ?? throw new ArgumentNullException(nameof(parameters));
        }

        public MLDsaKeyGenerationParameters(SecureRandom random, DerObjectIdentifier parametersOid)
            : base(random, 0)
        {
            if (parametersOid == null)
                throw new ArgumentNullException(nameof(parametersOid));
            if (!MLDsaParameters.ByOid.TryGetValue(parametersOid, out m_parameters))
                throw new ArgumentException("unrecognised ML-DSA parameters OID", nameof(parametersOid));
        }

        public MLDsaParameters Parameters => m_parameters;
    }
}
