#nullable disable
#pragma warning disable IL3050, IL2070, IL2026, IL2057, IL2059, IL2067, IL2072, IL2075, IL2080, IL2087, IL2090, IL2091, IL3051, CS3021, SYSLIB0051, CA1857, CS0105, CS1591, CA2014, CS8500

using System;

using Org.BouncyCastle.Math;

namespace Org.BouncyCastle.Asn1.X509
{
    public class RsaPublicKeyStructure
        : Asn1Encodable
    {
        public static RsaPublicKeyStructure GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is RsaPublicKeyStructure rsaPublicKeyStructure)
                return rsaPublicKeyStructure;
            return new RsaPublicKeyStructure(Asn1Sequence.GetInstance(obj));
        }

        public static RsaPublicKeyStructure GetInstance(Asn1TaggedObject obj, bool explicitly) =>
            new RsaPublicKeyStructure(Asn1Sequence.GetInstance(obj, explicitly));

        public static RsaPublicKeyStructure GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new RsaPublicKeyStructure(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private readonly BigInteger m_modulus;
        private readonly BigInteger m_publicExponent;

        private RsaPublicKeyStructure(Asn1Sequence seq)
        {
            int count = seq.Count;
            if (count != 2)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            // Note: we are accepting technically incorrect (i.e. negative) values here
            m_modulus = DerInteger.GetInstance(seq[0]).PositiveValue;
            m_publicExponent = DerInteger.GetInstance(seq[1]).PositiveValue;
        }

        public RsaPublicKeyStructure(BigInteger modulus, BigInteger publicExponent)
        {
            if (modulus == null)
				throw new ArgumentNullException("modulus");
			if (publicExponent == null)
				throw new ArgumentNullException("publicExponent");
			if (modulus.SignValue <= 0)
				throw new ArgumentException("Not a valid RSA modulus", "modulus");
			if (publicExponent.SignValue <= 0)
				throw new ArgumentException("Not a valid RSA public exponent", "publicExponent");

            m_modulus = modulus;
            m_publicExponent = publicExponent;
        }

        public BigInteger Modulus => m_modulus;

        public BigInteger PublicExponent => m_publicExponent;

		/**
         * This outputs the key in Pkcs1v2 format.
         * <pre>
         *      RSAPublicKey ::= Sequence {
         *                          modulus Integer, -- n
         *                          publicExponent Integer, -- e
         *                      }
         * </pre>
         */
        public override Asn1Object ToAsn1Object() =>
            new DerSequence(new DerInteger(m_modulus), new DerInteger(m_publicExponent));
    }
}
