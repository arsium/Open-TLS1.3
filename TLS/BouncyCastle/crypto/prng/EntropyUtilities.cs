#nullable disable
#pragma warning disable IL3050, IL2070, IL2026, IL2057, IL2059, IL2067, IL2072, IL2075, IL2080, IL2087, IL2090, IL2091, IL3051, CS3021, SYSLIB0051, CA1857, CS0105, CS1591, CA2014, CS8500

﻿using System;

using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Crypto.Prng
{
    public abstract class EntropyUtilities
    {
        /**
         * Generate numBytes worth of entropy from the passed in entropy source.
         *
         * @param entropySource the entropy source to request the data from.
         * @param numBytes the number of bytes of entropy requested.
         * @return a byte array populated with the random data.
         */
        public static byte[] GenerateSeed(IEntropySource entropySource, int numBytes)
        {
            byte[] bytes = new byte[numBytes];

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            GenerateSeed(entropySource, bytes);
#else
            int count = 0;
            while (count < numBytes)
            {
                byte[] entropy = entropySource.GetEntropy();
                int toCopy = System.Math.Min(bytes.Length, numBytes - count);
                Array.Copy(entropy, 0, bytes, count, toCopy);
                count += toCopy;
            }
#endif

            return bytes;
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public static void GenerateSeed(IEntropySource entropySource, Span<byte> seed)
        {
            while (!seed.IsEmpty)
            {
                int len = entropySource.GetEntropy(seed);
                seed = seed[len..];
            }
        }
#endif
    }
}
