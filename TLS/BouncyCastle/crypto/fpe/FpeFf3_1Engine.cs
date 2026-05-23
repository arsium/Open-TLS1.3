#nullable disable
#pragma warning disable IL3050, IL2070, IL2026, IL2057, IL2059, IL2067, IL2072, IL2075, IL2080, IL2087, IL2090, IL2091, IL3051, CS3021, SYSLIB0051, CA1857, CS0105, CS1591, CA2014, CS8500

using System;

using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Utilities;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto.Fpe
{
    public class FpeFf3_1Engine
        : FpeEngine
    {
        public FpeFf3_1Engine()
            : this(AesUtilities.CreateEngine())
        {
        }

        public FpeFf3_1Engine(IBlockCipher baseCipher)
            : base(baseCipher)
        {
            if (IsOverrideSet(SP80038G.FpeDisableProperty))
                throw new InvalidOperationException("FPE disabled");
        }

        public override void Init(bool forEncryption, ICipherParameters parameters)
        {
            this.forEncryption = forEncryption;
            this.fpeParameters = (FpeParameters)parameters;

            baseCipher.Init(!fpeParameters.UseInverseFunction, fpeParameters.Key.Reverse());

            if (fpeParameters.GetTweak().Length != 7)
                throw new ArgumentException("tweak should be 56 bits");
        }

        protected override int EncryptBlock(byte[] inBuf, int inOff, int length, byte[] outBuf, int outOff)
        {
            byte[] enc;

            if (fpeParameters.Radix > 256)
            {
                if ((length & 1) != 0)
                    throw new ArgumentException("input must be an even number of bytes for a wide radix");

                ushort[] u16In = Pack.BE_To_UInt16(inBuf, inOff, length / 2);
                ushort[] u16Out = SP80038G.EncryptFF3_1w(baseCipher, fpeParameters.Radix, fpeParameters.GetTweak(),
                    u16In, 0, u16In.Length);
                enc = Pack.UInt16_To_BE(u16Out, 0, u16Out.Length);
            }
            else
            {
                enc = SP80038G.EncryptFF3_1(baseCipher, fpeParameters.Radix, fpeParameters.GetTweak(), inBuf, inOff, length);
            }

            Array.Copy(enc, 0, outBuf, outOff, length);

            return length;
        }

        protected override int DecryptBlock(byte[] inBuf, int inOff, int length, byte[] outBuf, int outOff)
        {
            byte[] dec;

            if (fpeParameters.Radix > 256)
            {
                if ((length & 1) != 0)
                    throw new ArgumentException("input must be an even number of bytes for a wide radix");

                ushort[] u16In = Pack.BE_To_UInt16(inBuf, inOff, length / 2);
                ushort[] u16Out = SP80038G.DecryptFF3_1w(baseCipher, fpeParameters.Radix, fpeParameters.GetTweak(),
                    u16In, 0, u16In.Length);
                dec = Pack.UInt16_To_BE(u16Out, 0, u16Out.Length);
            }
            else
            {
                dec = SP80038G.DecryptFF3_1(baseCipher, fpeParameters.Radix, fpeParameters.GetTweak(), inBuf, inOff, length);
            }

            Array.Copy(dec, 0, outBuf, outOff, length);

            return length;
        }
    }
}
