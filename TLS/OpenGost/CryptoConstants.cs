namespace OpenGost.Security.Cryptography;

internal static class CryptoConstants
{
    public const string GostECDsaAlgorithmName = "GostECDsa";

    public const string GrasshopperAlgorithmName = nameof(Grasshopper);
    public const string CMACGrasshopperAlgorithmName = nameof(CMACGrasshopper);
    public const string MagmaAlgorithmName = nameof(Magma);
    public const string CMACMagmaAlgorithmName = nameof(CMACMagma);

    public const string Streebog256AlgorithmName = nameof(Streebog256);
    public const string Streebog512AlgorithmName = nameof(Streebog512);
}
