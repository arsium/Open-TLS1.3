#nullable disable
#pragma warning disable IL3050, IL2070, IL2026, IL2057, IL2059, IL2067, IL2072, IL2075, IL2080, IL2087, IL2090, IL2091, IL3051, CS3021, SYSLIB0051, CA1857, CS0105, CS1591, CA2014, CS8500

using System;

namespace Org.BouncyCastle.Crypto.Modes.Gcm
{
    [Obsolete("Will be removed")]
    public class BasicGcmExponentiator
        : IGcmExponentiator
    {
        private GcmUtilities.FieldElement x;

        public void Init(byte[] x)
        {
            GcmUtilities.AsFieldElement(x, out this.x);
        }

        public void ExponentiateX(long pow, byte[] output)
        {
            GcmUtilities.FieldElement y;
            GcmUtilities.One(out y);

            if (pow > 0)
            {
                GcmUtilities.FieldElement powX = x;
                do
                {
                    if ((pow & 1L) != 0)
                    {
                        GcmUtilities.Multiply(ref y, ref powX);
                    }
                    GcmUtilities.Square(ref powX);
                    pow >>= 1;
                }
                while (pow > 0);
            }

            GcmUtilities.AsBytes(ref y, output);
        }
    }
}
