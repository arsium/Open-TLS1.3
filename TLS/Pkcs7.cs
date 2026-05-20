namespace TLS;

/// <summary>
/// PKCS#7 / CMS SignedData certificate bundle parser (RFC 2315 / RFC 5652).
/// Extracts X.509 certificates from .p7b / .p7c files.
/// </summary>
public static class Pkcs7
{
    // OIDs
    private const string OidSignedData = "1.2.840.113549.1.7.2";

    /// <summary>
    /// Import certificates from a PKCS#7 / CMS DER-encoded bundle.
    /// Parses the SignedData structure and extracts the [0] IMPLICIT certificate set.
    /// </summary>
    public static byte[][] Import(byte[] data)
    {
        // ContentInfo ::= SEQUENCE { contentType OID, content [0] EXPLICIT ANY }
        var (_, ciValue, _) = Asn1.ReadTlv(data);
        var ciItems = Asn1.ReadSequenceItems(ciValue);

        if (ciItems.Count < 2)
            throw new TlsException(AlertDescription.DecodeError, "Invalid PKCS#7 ContentInfo");

        // Verify contentType is signedData (1.2.840.113549.1.7.2)
        byte[] oid = Asn1.Wrap(ciItems[0].tag, ciItems[0].value);
        byte[] signedDataOid = Asn1.Oid(OidSignedData);
        if (!oid.AsSpan().SequenceEqual(signedDataOid))
            throw new TlsException(AlertDescription.DecodeError,
                "PKCS#7 contentType is not signedData");

        // content [0] EXPLICIT wraps the SignedData SEQUENCE
        var (_, signedDataContent, _) = Asn1.ReadTlv(ciItems[1].value);

        // SignedData ::= SEQUENCE {
        //   version          CMSVersion,
        //   digestAlgorithms DigestAlgorithmIdentifiers,
        //   encapContentInfo EncapsulatedContentInfo,
        //   certificates [0] IMPLICIT CertificateSet OPTIONAL,
        //   crls         [1] IMPLICIT RevocationInfoChoices OPTIONAL,
        //   signerInfos  SignerInfos
        // }
        var sdItems = Asn1.ReadSequenceItems(signedDataContent);

        var certs = new List<byte[]>();
        for (int i = 0; i < sdItems.Count; i++)
        {
            if (sdItems[i].tag == 0xA0) // [0] IMPLICIT certificates
            {
                // Content is concatenated Certificate TLVs
                var certEntries = Asn1.ReadSequenceItems(sdItems[i].value);
                foreach (var (tag, value) in certEntries)
                    certs.Add(Asn1.Wrap(tag, value)); // reconstruct full DER
                break;
            }
        }

        return certs.ToArray();
    }

    /// <summary>Import certificates from a PEM-encoded PKCS#7 bundle.</summary>
    public static byte[][] ImportPem(string pem)
    {
        var blocks = CertificateUtils.ParsePemBlocks(pem);
        foreach (var (label, data) in blocks)
        {
            if (label is "PKCS7" or "CMS")
                return Import(data);
        }
        throw new TlsException(AlertDescription.DecodeError,
            "PEM does not contain a PKCS7 or CMS block");
    }
}
