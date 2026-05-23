#nullable disable
#pragma warning disable IL3050, IL2070, IL2026, IL2057, IL2059, IL2067, IL2072, IL2075, IL2080, IL2087, IL2090, IL2091, IL3051, CS3021, SYSLIB0051, CA1857, CS0105, CS1591, CA2014, CS8500

namespace Org.BouncyCastle.Math.EC.Multiplier
{
    /**
    * Interface for classes encapsulating a point multiplication algorithm
    * for <code>ECPoint</code>s.
    */
    public interface ECMultiplier
    {
        /**
         * Multiplies the <code>ECPoint p</code> by <code>k</code>, i.e.
         * <code>p</code> is added <code>k</code> times to itself.
         * @param p The <code>ECPoint</code> to be multiplied.
         * @param k The factor by which <code>p</code> is multiplied.
         * @return <code>p</code> multiplied by <code>k</code>.
         */
        ECPoint Multiply(ECPoint p, BigInteger k);
    }
}
