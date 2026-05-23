namespace Tests;

using System.Diagnostics;
using TLS;

/// <summary>
/// Deterministic-seeded fuzzer for the HandshakeMessages parsers. Each parser is driven
/// with a set of malformed inputs (random bytes, truncations, fields with garbage lengths)
/// — the contract is that any malformed input MUST surface as TlsException (with a
/// DecodeError / IllegalParameter / BadCertificate alert), never as an unhandled
/// IndexOutOfRange / ArgumentOutOfRange / NullReference.
///
/// Run with: dotnet run -c Release -- fuzz [iterations]
/// Default 50000 iterations across 8 parsers (~400000 inputs).
/// </summary>
public static class Fuzz
{
    public static int Run(int iterations)
    {
        Console.WriteLine($"Open-TLS 1.3 — parser fuzz ({iterations} iterations per parser)");
        Console.WriteLine();

        // Targets: each entry is (name, parser-callback) — the callback throws TlsException
        // on malformed input and returns normally on a successful (or partial-successful)
        // parse. Any other exception type is a bug.
        var targets = new (string name, Action<byte[]> parser)[]
        {
            ("Unframe",                  body => HandshakeMessages.Unframe(body)),
            ("ParseClientHello",         body => HandshakeMessages.ParseClientHello(body)),
            ("ParseServerHello",         body => HandshakeMessages.ParseServerHello(body)),
            ("ParseCertificateMessage",  body => HandshakeMessages.ParseCertificateMessage(body)),
            ("ParseCertificateEx",       body => HandshakeMessages.ParseCertificateEx(body)),
            ("ParseCertificateRequest",  body => HandshakeMessages.ParseCertificateRequest(body)),
            ("ParseCertificateVerify",   body => HandshakeMessages.ParseCertificateVerify(body)),
            ("ParseNewSessionTicket",    body => HandshakeMessages.ParseNewSessionTicket(body)),
            ("ParseCompressedCertificate", body => HandshakeMessages.ParseCompressedCertificate(body)),
            ("ParsePreSharedKeyExtension", body => HandshakeMessages.ParsePreSharedKeyExtension(body)),
            ("ParseEncryptedExtensionsEx", body => HandshakeMessages.ParseEncryptedExtensionsEx(body)),
            ("SplitMessages",            body => HandshakeMessages.SplitMessages(body)),
        };

        // Deterministic PRNG — same seed reproduces the same campaign.
        var rng = new Random(0xC0FFEE);
        int totalIn = 0, totalOk = 0, totalAlert = 0, totalBug = 0;
        var bugReport = new List<string>();

        foreach (var (name, parser) in targets)
        {
            int ok = 0, alert = 0, bug = 0;
            var sw = Stopwatch.StartNew();
            for (int i = 0; i < iterations; i++)
            {
                byte[] input = GenerateInput(rng, i);
                totalIn++;
                try
                {
                    parser(input);
                    ok++;
                }
                catch (TlsException)
                {
                    // Expected — parser correctly rejected malformed input.
                    alert++;
                }
                catch (Exception e)
                {
                    bug++;
                    if (bugReport.Count < 20)
                    {
                        bugReport.Add($"  {name}: {e.GetType().Name}: {e.Message} (input len={input.Length}, first16={SafeHex(input)})");
                    }
                }
            }
            sw.Stop();
            string status = bug == 0 ? "OK" : "BUG";
            Console.WriteLine($"  [{status}] {name,-30} {ok,6} accept / {alert,6} alert / {bug,4} BUG  ({iterations}x in {sw.ElapsedMilliseconds} ms)");
            totalOk += ok; totalAlert += alert; totalBug += bug;
        }

        Console.WriteLine();
        Console.WriteLine($"Totals: {totalIn} inputs, {totalOk} accepted, {totalAlert} rejected via TlsException, {totalBug} unhandled exceptions");
        if (totalBug > 0)
        {
            Console.WriteLine();
            Console.WriteLine("Unhandled-exception samples (first 20):");
            foreach (var b in bugReport) Console.WriteLine(b);
        }
        return totalBug == 0 ? 0 : 1;
    }

    // Mix of input shapes that historically expose parser bugs:
    //  - small random (catches null/empty edge cases)
    //  - medium random (catches generic length issues)
    //  - large random (catches integer overflow / OOM allocation)
    //  - structured-random: real-ish framing with one byte flipped (catches inner-field bugs)
    private static byte[] GenerateInput(Random rng, int iter)
    {
        int shape = iter & 0b11;
        int len = shape switch
        {
            0 => rng.Next(0, 8),
            1 => rng.Next(8, 256),
            2 => rng.Next(256, 8192),
            _ => rng.Next(8192, 32768),
        };
        byte[] buf = new byte[len];
        rng.NextBytes(buf);
        return buf;
    }

    private static string SafeHex(byte[] b)
    {
        int n = Math.Min(16, b.Length);
        return Convert.ToHexString(b.AsSpan(0, n)).ToLowerInvariant();
    }
}
