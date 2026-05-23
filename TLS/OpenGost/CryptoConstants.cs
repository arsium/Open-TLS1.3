using System.Security.Cryptography;
using System.Numerics;
﻿namespace OpenGost.Security.Cryptography;

internal static class CryptoConstants
{
    public const string GostECDsaAlgorithmName = "GostECDsa";

    public const string GrasshopperAlgorithmName = nameof(GrasshopperManaged);
    public const string MagmaAlgorithmName = nameof(MagmaManaged);

    public const string Streebog256AlgorithmName = nameof(Streebog256Managed);
    public const string Streebog512AlgorithmName = nameof(Streebog512Managed);
}
