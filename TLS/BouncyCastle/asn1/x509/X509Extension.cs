#nullable disable
#pragma warning disable IL3050, IL2070, IL2026, IL2057, IL2059, IL2067, IL2072, IL2075, IL2080, IL2087, IL2090, IL2091, IL3051, CS3021, SYSLIB0051, CA1857, CS0105, CS1591, CA2014, CS8500

using System;

namespace Org.BouncyCastle.Asn1.X509
{
    /**
     * an object for the elements in the X.509 V3 extension block.
     */
    public class X509Extension
    {
        private readonly bool m_critical;
        private readonly Asn1OctetString m_value;

        public X509Extension(DerBoolean critical, Asn1OctetString value)
        {
            m_critical = critical?.IsTrue ?? throw new ArgumentNullException(nameof(critical));
            m_value = value ?? throw new ArgumentNullException(nameof(value));
        }

        public X509Extension(bool critical, Asn1OctetString value)
        {
            m_critical = critical;
            m_value = value ?? throw new ArgumentNullException(nameof(value));
        }

        public bool IsCritical => m_critical;

        public Asn1OctetString Value => m_value;

        public Asn1Object GetParsedValue() => ConvertValueToObject(this);

        public override int GetHashCode()
        {
            int vh = Value.GetHashCode();

            return IsCritical ? vh : ~vh;
        }

        public override bool Equals(object obj)
        {
            return obj is X509Extension that
                && this.Value.Equals(that.Value)
                && this.IsCritical == that.IsCritical;
        }

        /// <sumary>Convert the value of the passed in extension to an object.</sumary>
        /// <param name="ext">The extension to parse.</param>
        /// <returns>The object the value string contains.</returns>
        /// <exception cref="ArgumentException">If conversion is not possible.</exception>
        public static Asn1Object ConvertValueToObject(X509Extension ext) => Extension.ConvertValueToObject(ext.Value);
    }
}
