namespace OpenGost.Security.Cryptography.Properties;

// Vendored from OpenGost: resx-backed strongly-typed resources replaced with
// literal strings so the source compiles AOT-safe without embedded resources.
internal static class CryptographyStrings
{
    internal static string ArgumentInvalidOffLen => "Offset and length were out of bounds for the array or count is greater than the number of elements from index to the end of the source collection.";
    internal static string ArgumentOutOfRangeNeedNonNegNum => "Non-negative number required.";
    internal static string ArgumentOutOfRangeNeedPositiveNum => "Positive number required.";
    internal static string CryptographicDerInvalidEncoding => "ASN1 corrupted data.";
    internal static string CryptographicHashKeySet => "Hash key cannot be changed after the first write to the stream.";
    internal static string CryptographicInsufficientOutputBuffer => "Output buffer contains insufficient data size.";
    internal static string CryptographicInvalidBlockSize => "Specified block size is not valid for this algorithm.";
    internal static string CryptographicInvalidCipherMode => "Specified cipher mode is not valid for this algorithm.";
    internal static string CryptographicInvalidPaddingMode => "Specified padding mode is not valid for this algorithm.";
    internal static string CryptographicInvalidDataSize => "Length of the data to transform is invalid.";
    internal static string CryptographicInvalidFeedbackSize => "Specified feedback is not a valid for this algorithm.";
    internal static string CryptographicInvalidHashSize => "Hash size must be {0} bytes.";
    internal static string CryptographicInvalidIVSize => "Specified initialization vector (IV) does not match allowed size for this algorithm.";
    internal static string CryptographicInvalidPadding => "Padding is invalid and cannot be removed.";
    internal static string CryptographicInvalidSignatureSize => "Digital signature size must be {0} bytes.";
    internal static string CryptographicSymmetricAlgorithmKeySet => "The key cannot be changed after the first write to the stream.";
    internal static string CryptographicSymmetricAlgorithmNameNullOrEmpty => "The symmetric algorithm name cannot be null or empty.";
    internal static string CryptographicSymmetricAlgorithmNameSet => "Symmetric algorithm name cannot be changed after the first write to the stream.";
    internal static string CryptographicUnknownOid => "'{0}' is not a known object identifier.";
    internal static string CryptographicUnknownSymmetricAlgorithm => "'{0}' is not a known symmetric algorithm.";
}
