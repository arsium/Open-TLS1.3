#nullable disable
#pragma warning disable IL3050, IL2070, IL2026, IL2057, IL2059, IL2067, IL2072, IL2075, IL2080, IL2087, IL2090, IL2091, IL3051, CS3021, SYSLIB0051, CA1857, CS0105, CS1591, CA2014, CS8500

﻿using System;

using Org.BouncyCastle.Asn1;

namespace Org.BouncyCastle.Crypto.Utilities
{
    internal class DerUtilities
    {
        internal static Asn1OctetString GetOctetString(byte[] data)
        {
            byte[] contents = data == null ? Array.Empty<byte>() : (byte[])data.Clone();

            return new DerOctetString(contents);
        }

        internal static byte[] ToByteArray(Asn1Object asn1Object)
        {
            return asn1Object.GetEncoded();
        }
    }
}
