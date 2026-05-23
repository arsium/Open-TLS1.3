#nullable disable
#pragma warning disable IL3050, IL2070, IL2026, IL2057, IL2059, IL2067, IL2072, IL2075, IL2080, IL2087, IL2090, IL2091, IL3051, CS3021, SYSLIB0051, CA1857, CS0105, CS1591, CA2014, CS8500

﻿using System.Collections.Generic;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Nist;
using Org.BouncyCastle.Asn1.Ntt;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Operators;

namespace Org.BouncyCastle.Operators
{
    public class CmsContentEncryptorBuilder
    {
        private static readonly IDictionary<DerObjectIdentifier, int> KeySizes =
            new Dictionary<DerObjectIdentifier, int>();

        static CmsContentEncryptorBuilder()
        {
            KeySizes[NistObjectIdentifiers.IdAes128Cbc] = 128;
            KeySizes[NistObjectIdentifiers.IdAes192Cbc] = 192;
            KeySizes[NistObjectIdentifiers.IdAes256Cbc] = 256;

            KeySizes[NttObjectIdentifiers.IdCamellia128Cbc] = 128;
            KeySizes[NttObjectIdentifiers.IdCamellia192Cbc] = 192;
            KeySizes[NttObjectIdentifiers.IdCamellia256Cbc] = 256;
        }

        private static int GetKeySize(DerObjectIdentifier oid)
        {
            return KeySizes.TryGetValue(oid, out var keySize) ? keySize : -1;
        }

        private readonly DerObjectIdentifier encryptionOID;
        private readonly int keySize;

        //private SecureRandom random;

        public CmsContentEncryptorBuilder(DerObjectIdentifier encryptionOID)
            : this(encryptionOID, GetKeySize(encryptionOID))
        {
        }

        public CmsContentEncryptorBuilder(DerObjectIdentifier encryptionOID, int keySize)
        {
            this.encryptionOID = encryptionOID;
            this.keySize = keySize;
        }

        public ICipherBuilderWithKey Build()
        {
            //return new Asn1CipherBuilderWithKey(encryptionOID, keySize, random);
            return new Asn1CipherBuilderWithKey(encryptionOID, keySize, null);
        }
    }
}
