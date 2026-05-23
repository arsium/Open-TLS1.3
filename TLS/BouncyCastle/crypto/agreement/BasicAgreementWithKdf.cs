#nullable disable
#pragma warning disable IL3050, IL2070, IL2026, IL2057, IL2059, IL2067, IL2072, IL2075, IL2080, IL2087, IL2090, IL2091, IL3051, CS3021, SYSLIB0051, CA1857, CS0105, CS1591, CA2014, CS8500

﻿using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Crypto.Agreement.Kdf;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto.Agreement
{
    internal static class BasicAgreementWithKdf
    {
        internal static BigInteger CalculateAgreementWithKdf(string algorithm, IDerivationFunction kdf, int fieldSize,
            BigInteger result)
        {
            // Note that the ec.KeyAgreement class in JCE only uses kdf in oneof the engineGenerateSecret methods.

            int keySize = GeneratorUtilities.GetDefaultKeySize(algorithm);

            DHKdfParameters dhKdfParams = new DHKdfParameters(
                new DerObjectIdentifier(algorithm),
                keySize,
                BigIntegers.AsUnsignedByteArray(fieldSize, result));

            kdf.Init(dhKdfParams);

            byte[] keyBytes = new byte[keySize / 8];
            kdf.GenerateBytes(keyBytes, 0, keyBytes.Length);

            return new BigInteger(1, keyBytes);
        }
    }
}
