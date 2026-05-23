#nullable disable
#pragma warning disable IL3050, IL2070, IL2026, IL2057, IL2059, IL2067, IL2072, IL2075, IL2080, IL2087, IL2090, IL2091, IL3051, CS3021, SYSLIB0051, CA1857, CS0105, CS1591, CA2014, CS8500

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Cms;
using Org.BouncyCastle.Asn1.X509;

namespace Org.BouncyCastle.Asn1.Smime
{
    /**
     * The SmimeEncryptionKeyPreference object.
     * <pre>
     * SmimeEncryptionKeyPreference ::= CHOICE {
     *     issuerAndSerialNumber   [0] IssuerAndSerialNumber,
     *     receipentKeyId          [1] RecipientKeyIdentifier,
     *     subjectAltKeyIdentifier [2] SubjectKeyIdentifier
     * }
     * </pre>
     */
    public class SmimeEncryptionKeyPreferenceAttribute
        : AttributeX509
    {
        public SmimeEncryptionKeyPreferenceAttribute(
            IssuerAndSerialNumber issAndSer)
            : base(SmimeAttributes.EncrypKeyPref,
                new DerSet(new DerTaggedObject(false, 0, issAndSer)))
        {
        }

        public SmimeEncryptionKeyPreferenceAttribute(
            RecipientKeyIdentifier rKeyID)
            : base(SmimeAttributes.EncrypKeyPref,
                new DerSet(new DerTaggedObject(false, 1, rKeyID)))
        {
        }

        /**
         * @param sKeyId the subjectKeyIdentifier value (normally the X.509 one)
         */
        public SmimeEncryptionKeyPreferenceAttribute(
            Asn1OctetString sKeyID)
            : base(SmimeAttributes.EncrypKeyPref,
                new DerSet(new DerTaggedObject(false, 2, sKeyID)))
        {
        }
    }
}
