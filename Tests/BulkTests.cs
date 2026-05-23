namespace Tests;

using System.Diagnostics;
using System.Security.Cryptography;
using TLS;

/// <summary>
/// Loopback bulk-data tests for 20 MB and 50 MB payloads across the
/// AEAD-fast cipher suites. Each test:
///   1. Generates a random payload.
///   2. Client sends it; server reads, hashes, and echoes a SHA-256.
///   3. Client checks the hash matches the local SHA-256.
///   4. Reports send-side throughput.
///
/// SM4 / MGM are skipped because their AEAD throughput (5-33 MB/s)
/// would make 50 MB take 1.5-10 seconds per direction — not useful
/// for a correctness/perf smoke test.
/// </summary>
public static class BulkTests
{
    private static int _port = 22000;

    public static int Run()
    {
        Console.WriteLine("Open-TLS 1.3 — bulk-data loopback suite");
        Console.WriteLine();

        var ca = CertificateUtils.GenerateCA("Bulk Test CA");
        var ecCert = CertificateUtils.IssueCertificate("localhost", ca, CertificateProfile.Server);

        var sizes = new[] { 20 * 1024 * 1024, 50 * 1024 * 1024 };
        var suites = new List<(CipherSuite suite, string label)>
        {
            (CipherSuite.TLS_AES_128_GCM_SHA256, "AES-128-GCM"),
            (CipherSuite.TLS_AES_256_GCM_SHA384, "AES-256-GCM"),
            // AeadCipher transparently falls back to ChaCha20Poly1305Managed (RFC 8439, pure C#)
            // when the BCL ChaCha20Poly1305 isn't supported by the underlying OS / crypto provider.
            (CipherSuite.TLS_CHACHA20_POLY1305_SHA256, "ChaCha20-Poly1305"),
        };
        if (!ChaCha20Poly1305.IsSupported)
            Console.WriteLine("(BCL ChaCha20Poly1305 not supported on this OS — using the managed RFC 8439 fallback)\n");

        int passes = 0, fails = 0;
        foreach (int size in sizes)
        {
            string mb = (size / (1024 * 1024)).ToString();
            T.Section($"Bulk loopback: {mb} MB payloads");
            foreach (var (suite, label) in suites)
            {
                bool ok = RunOne(label, ecCert, suite, size);
                if (ok) passes++; else fails++;
            }
        }

        Console.WriteLine();
        Console.WriteLine($"========================================");
        Console.WriteLine($"{passes} passed, {fails} failed");
        return fails == 0 ? 0 : 1;
    }

    private static bool RunOne(string label, TlsCertificate cert, CipherSuite suite, int size)
    {
        int port = ++_port;
        var server = new TlsServer(cert);
        server.Listen(port);

        // Generate random payload + reference hash.
        byte[] payload = new byte[size];
        RandomNumberGenerator.Fill(payload);
        byte[] expectedHash = SHA256.HashData(payload);

        var srv = Task.Run(() =>
        {
            try
            {
                using var s = server.Accept();
                // Receive size bytes, hash them, echo the hash.
                using var sha = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
                byte[] rbuf = new byte[64 * 1024];
                long got = 0;
                while (got < size)
                {
                    int n = s.Read(rbuf, 0, rbuf.Length);
                    if (n <= 0) break;
                    sha.AppendData(rbuf, 0, n);
                    got += n;
                }
                byte[] serverHash = sha.GetHashAndReset();
                s.Write(serverHash, 0, serverHash.Length);
                Thread.Sleep(100);
            }
            catch (Exception e) { Console.WriteLine($"  [server error] {e.GetType().Name}: {e.Message}"); }
        });

        try
        {
            var c = new TlsClient
            {
                HandshakeTimeoutMs = 12000,
                CipherSuites = new[] { suite },
            };
            using var st = c.Connect("localhost", port);

            var sw = Stopwatch.StartNew();
            st.Write(payload);
            sw.Stop();
            double sendMs = sw.Elapsed.TotalMilliseconds;
            double sendMBs = (size / (1024.0 * 1024.0)) / (sendMs / 1000.0);

            // Read server's echoed SHA-256 (32 bytes).
            byte[] serverHash = new byte[32];
            int got = 0;
            while (got < 32)
            {
                int n = st.Read(serverHash, got, 32 - got);
                if (n <= 0) break;
                got += n;
            }

            bool ok = got == 32 && serverHash.AsSpan().SequenceEqual(expectedHash);
            string sizeMb = (size / (1024 * 1024)).ToString();
            string status = ok ? "PASS" : "FAIL";
            Console.WriteLine($"  {status}  {label,-22} {sizeMb,3} MB   send {sendMs,7:F1} ms   {sendMBs,7:F1} MB/s");
            return ok;
        }
        catch (Exception e)
        {
            Console.WriteLine($"  FAIL  {label}: {e.GetType().Name}: {e.Message}");
            return false;
        }
        finally
        {
            srv.Wait(120000);
            server.Stop();
        }
    }
}
