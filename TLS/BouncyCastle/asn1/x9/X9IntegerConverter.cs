#nullable disable
#pragma warning disable IL3050, IL2070, IL2026, IL2057, IL2059, IL2067, IL2072, IL2075, IL2080, IL2087, IL2090, IL2091, IL3051, CS3021, SYSLIB0051, CA1857, CS0105, CS1591, CA2014, CS8500

using System;

using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;

namespace Org.BouncyCastle.Asn1.X9
{
    // TODO[api] Make static
    public abstract class X9IntegerConverter
    {
        public static int GetByteLength(ECFieldElement fe) => fe.GetEncodedLength();

        public static int GetByteLength(ECCurve c) => c.FieldElementEncodingLength;

        public static byte[] IntegerToBytes(BigInteger s, int qLength)
        {
            byte[] bytes = s.ToByteArrayUnsigned();

            if (qLength < bytes.Length)
            {
                byte[] tmp = new byte[qLength];
                Array.Copy(bytes, bytes.Length - tmp.Length, tmp, 0, tmp.Length);
                return tmp;
            }
            else if (qLength > bytes.Length)
            {
                byte[] tmp = new byte[qLength];
                Array.Copy(bytes, 0, tmp, tmp.Length - bytes.Length, bytes.Length);
                return tmp;
            }

            return bytes;
        }
    }
}
