#nullable disable
#pragma warning disable IL3050, IL2070, IL2026, IL2057, IL2059, IL2067, IL2072, IL2075, IL2080, IL2087, IL2090, IL2091, IL3051, CS3021, SYSLIB0051, CA1857, CS0105, CS1591, CA2014, CS8500

using System;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto.Parameters
{
public sealed class FpeParameters
    : ICipherParameters
{
    private readonly KeyParameter key;
    private readonly int radix;
    private readonly byte[] tweak;
    private readonly bool useInverse;

    public FpeParameters(KeyParameter key, int radix, byte[] tweak): this(key, radix, tweak, false)
    {
        
    }

    public FpeParameters(KeyParameter key, int radix, byte[] tweak, bool useInverse)
    {
        this.key = key;
        this.radix = radix;
        this.tweak = Arrays.Clone(tweak);
        this.useInverse = useInverse;
    }

    public KeyParameter Key
    {
        get { return key; }
    }

    public int Radix
    {
        get { return radix; }
    }

    public bool UseInverseFunction
    {
        get { return useInverse; }
    }

    public byte[] GetTweak()
    {
        return Arrays.Clone(tweak);
    }
}
}
