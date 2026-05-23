#nullable disable
#pragma warning disable IL3050, IL2070, IL2026, IL2057, IL2059, IL2067, IL2072, IL2075, IL2080, IL2087, IL2090, IL2091, IL3051, CS3021, SYSLIB0051, CA1857, CS0105, CS1591, CA2014, CS8500

﻿using System;
using System.IO;

using Org.BouncyCastle.Crypto.IO;

namespace Org.BouncyCastle.Crypto.Operators
{
    // TODO[api] sealed
    public class DefaultVerifierCalculator
        : IStreamCalculator<IVerifier>
    {
        private readonly SignerSink m_signerSink;

        public DefaultVerifierCalculator(ISigner signer)
        {
            m_signerSink = new SignerSink(signer);
        }

        public Stream Stream => m_signerSink;

        public IVerifier GetResult() => new DefaultVerifierResult(m_signerSink.Signer);
    }
}
