#nullable disable
#pragma warning disable IL3050, IL2070, IL2026, IL2057, IL2059, IL2067, IL2072, IL2075, IL2080, IL2087, IL2090, IL2091, IL3051, CS3021, SYSLIB0051, CA1857, CS0105, CS1591, CA2014, CS8500

﻿using System;

namespace Org.BouncyCastle.Crypto
{
    public interface IKemEncapsulator
    {
        void Init(ICipherParameters parameters);

        int EncapsulationLength { get; }

        int SecretLength { get; }

        void Encapsulate(byte[] encBuf, int encOff, int encLen, byte[] secBuf, int secOff, int secLen);

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        void Encapsulate(Span<byte> encapsulation, Span<byte> secret);
#endif
    }
}
