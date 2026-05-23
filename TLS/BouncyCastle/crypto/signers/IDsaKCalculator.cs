#nullable disable
#pragma warning disable IL3050, IL2070, IL2026, IL2057, IL2059, IL2067, IL2072, IL2075, IL2080, IL2087, IL2090, IL2091, IL3051, CS3021, SYSLIB0051, CA1857, CS0105, CS1591, CA2014, CS8500

﻿using System;

using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Crypto.Signers
{
    /**
     * Interface define calculators of K values for DSA/ECDSA.
     */
    public interface IDsaKCalculator
    {
        /**
         * Return true if this calculator is deterministic, false otherwise.
         *
         * @return true if deterministic, otherwise false.
         */
        bool IsDeterministic { get; }

        /**
         * Non-deterministic initialiser.
         *
         * @param n the order of the DSA group.
         * @param random a source of randomness.
         */
        void Init(BigInteger n, SecureRandom random);

        /**
         * Deterministic initialiser.
         *
         * @param n the order of the DSA group.
         * @param d the DSA private value.
         * @param message the message being signed.
         */
        void Init(BigInteger n, BigInteger d, byte[] message);

        /**
         * Return the next valid value of K.
         *
         * @return a K value.
         */
        BigInteger NextK();
    }
}
