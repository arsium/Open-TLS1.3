namespace Tests;

using System.Diagnostics;
using System.Security.Cryptography;
using TLS;

/// <summary>Rough throughput/latency benchmarks (run with `dotnet run -c Release --project Tests bench`).</summary>
public static class Benchmark
{
    public static void Run()
    {
        Console.WriteLine("\n== AEAD throughput (encrypt, 16 KiB records) ==");
        byte[] data = new byte[16384];
        RandomNumberGenerator.Fill(data);
        byte[] aad = new byte[5];

        AeadBench("AES-256-GCM", new AeadCipher(Key(32), Iv(12), AeadAlgorithm.AesGcm), data, aad);
        AeadBench("MGM-Kuznyechik", new AeadCipher(Key(32), Iv(16), AeadAlgorithm.MgmKuznyechik), data, aad);
        AeadBench("MGM-Magma", new AeadCipher(Key(32), Iv(8), AeadAlgorithm.MgmMagma), data, aad);
        AeadBench("SM4-GCM", new AeadCipher(Key(16), Iv(12), AeadAlgorithm.Sm4Gcm), data, aad);
        AeadBench("SM4-CCM", new AeadCipher(Key(16), Iv(12), AeadAlgorithm.Sm4Ccm), data, aad);

        Console.WriteLine("\n== Handshake latency (loopback, 10 iterations) ==");
        var ca = CertificateUtils.GenerateCA("Bench CA");
        var ec = CertificateUtils.IssueCertificate("localhost", ca, CertificateProfile.Server);
        var gost = CertificateUtils.IssueGostCertificate("localhost", ca, CertificateProfile.Server, SignatureScheme.Gostr34102012_256a);
        var sm2 = CertificateUtils.IssueSm2Certificate("localhost", ca, CertificateProfile.Server);
        HandshakeBench("default (X25519+AES)", ec, null, null);
        HandshakeBench("GOST (MGM+GC256A+GOST cert)", gost,
            new[] { CipherSuite.TLS_GOSTR341112_256_WITH_KUZNYECHIK_MGM_L }, new[] { NamedGroup.GC256A });
        HandshakeBench("SM (SM4-GCM+curveSM2+SM2 cert)", sm2,
            new[] { CipherSuite.TLS_SM4_GCM_SM3 }, new[] { NamedGroup.Curvesm2 });
    }

    private static void AeadBench(string name, AeadCipher c, byte[] data, byte[] aad)
    {
        for (int i = 0; i < 64; i++) c.Encrypt(data, aad); // warmup
        var sw = Stopwatch.StartNew();
        const int n = 2000;
        long bytes = 0;
        for (int i = 0; i < n; i++) { c.Encrypt(data, aad); bytes += data.Length; }
        sw.Stop();
        double mbps = bytes / 1e6 / sw.Elapsed.TotalSeconds;
        Console.WriteLine($"  {name,-16} {mbps,8:F1} MB/s");
    }

    private static int _port = 23000;
    private static void HandshakeBench(string name, TlsCertificate cert, CipherSuite[]? suites, NamedGroup[]? groups)
    {
        // warmup
        DoHandshake(cert, suites, groups);
        var sw = Stopwatch.StartNew();
        const int n = 10;
        for (int i = 0; i < n; i++) DoHandshake(cert, suites, groups);
        sw.Stop();
        Console.WriteLine($"  {name,-32} {sw.Elapsed.TotalMilliseconds / n,7:F1} ms/handshake");
    }

    private static void DoHandshake(TlsCertificate cert, CipherSuite[]? suites, NamedGroup[]? groups)
    {
        int port = ++_port;
        var server = new TlsServer(cert);
        server.Listen(port);
        var srv = Task.Run(() => { try { using var s = server.Accept(); var b = new byte[64]; int n = s.Read(b); s.Write(b, 0, n); } catch { } });
        var c = new TlsClient { HandshakeTimeoutMs = 12000 };
        if (suites != null) c.CipherSuites = suites;
        if (groups != null) c.NamedGroups = groups;
        using (var st = c.Connect("localhost", port))
        {
            st.Write(new byte[] { 1, 2, 3 });
            var b = new byte[64]; st.Read(b);
        }
        srv.Wait(6000); server.Stop();
    }

    private static byte[] Key(int n) { var k = new byte[n]; RandomNumberGenerator.Fill(k); return k; }
    private static byte[] Iv(int n) { var v = new byte[n]; RandomNumberGenerator.Fill(v); return v; }
}
