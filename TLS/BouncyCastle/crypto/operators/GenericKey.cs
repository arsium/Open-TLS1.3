#nullable disable
#pragma warning disable IL3050, IL2070, IL2026, IL2057, IL2059, IL2067, IL2072, IL2075, IL2080, IL2087, IL2090, IL2091, IL3051, CS3021, SYSLIB0051, CA1857, CS0105, CS1591, CA2014, CS8500

﻿using System;

using Org.BouncyCastle.Asn1.X509;

namespace Org.BouncyCastle.Crypto.Operators
{
    public class GenericKey
    {
        private readonly AlgorithmIdentifier algorithmIdentifier;
        private readonly object representation;

        public GenericKey(object representation)
        {
            this.algorithmIdentifier = null;
            this.representation = representation;
        }

        public GenericKey(AlgorithmIdentifier algorithmIdentifier, byte[] representation)
        {
            this.algorithmIdentifier = algorithmIdentifier;
            this.representation = representation;
        }

        public GenericKey(AlgorithmIdentifier algorithmIdentifier, object representation)
        {
            this.algorithmIdentifier = algorithmIdentifier;
            this.representation = representation;
        }

        public AlgorithmIdentifier AlgorithmIdentifier
        {
            get { return algorithmIdentifier; }
        }

        public object Representation
        {
            get { return representation; }
        }
    }
}
