#nullable disable
#pragma warning disable IL3050, IL2070, IL2026, IL2057, IL2059, IL2067, IL2072, IL2075, IL2080, IL2087, IL2090, IL2091, IL3051, CS3021, SYSLIB0051, CA1857, CS0105, CS1591, CA2014, CS8500

﻿using System;

using Org.BouncyCastle.Crypto.Parameters;

namespace Org.BouncyCastle.Crypto.Agreement
{
    public sealed class X448Agreement
        : IRawAgreement
    {
        private X448PrivateKeyParameters m_privateKey;

        public void Init(ICipherParameters parameters)
        {
            m_privateKey = (X448PrivateKeyParameters)parameters;
        }

        public int AgreementSize
        {
            get { return X448PrivateKeyParameters.SecretSize; }
        }

        public void CalculateAgreement(ICipherParameters publicKey, byte[] buf, int off)
        {
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            CalculateAgreement(publicKey, buf.AsSpan(off));
#else
            m_privateKey.GenerateSecret((X448PublicKeyParameters)publicKey, buf, off);
#endif
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public void CalculateAgreement(ICipherParameters publicKey, Span<byte> buf)
        {
            m_privateKey.GenerateSecret((X448PublicKeyParameters)publicKey, buf);
        }
#endif
    }
}
