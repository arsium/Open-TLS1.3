namespace Tests;

/// <summary>Minimal dependency-free test harness: PASS/FAIL lines + a failure count for the exit code.</summary>
public static class T
{
    private static int _total;
    public static int Failures { get; private set; }

    public static void Section(string name) => Console.WriteLine($"\n== {name} ==");

    public static void Check(string name, bool ok)
    {
        _total++;
        if (!ok) Failures++;
        Console.WriteLine($"  {(ok ? "PASS" : "FAIL")}  {name}");
    }

    public static void Eq(string name, string got, string exp)
    {
        bool ok = got == exp;
        Check(name, ok);
        if (!ok)
        {
            Console.WriteLine($"        got = {got}");
            Console.WriteLine($"        exp = {exp}");
        }
    }

    public static int Summary()
    {
        Console.WriteLine($"\n{'='.ToString().PadRight(40, '=')}");
        Console.WriteLine($"{_total - Failures}/{_total} passed, {Failures} failed");
        return Failures == 0 ? 0 : 1;
    }

    public static byte[] H(string hex) => Convert.FromHexString(hex.Replace(" ", "").Replace("\n", ""));
    public static string X(byte[] b) => Convert.ToHexString(b).ToLowerInvariant();
    public static bool Eqb(byte[] a, byte[] b) => a.AsSpan().SequenceEqual(b);
}
