#nullable disable
#pragma warning disable IL3050, IL2070, IL2026, IL2057, IL2059, IL2067, IL2072, IL2075, IL2080, IL2087, IL2090, IL2091, IL3051, CS3021, SYSLIB0051, CA1857, CS0105, CS1591, CA2014, CS8500

﻿using System;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto.Operators
{
    // TODO[api] sealed
    public class DefaultVerifierResult
        : IVerifier
    {
        private readonly ISigner m_signer;

        public DefaultVerifierResult(ISigner signer)
        {
            m_signer = signer;
        }

        public bool IsVerified(byte[] signature) => m_signer.VerifySignature(signature);

        // TODO[api] Use ISigner.VerifySignature(ReadOnlySpan<byte>) when available
        public bool IsVerified(byte[] sig, int sigOff, int sigLen) =>
            IsVerified(Arrays.CopyOfRange(sig, sigOff, sigOff + sigLen));
    }
}
