namespace Tests;

using System.Diagnostics;
using System.Security.Cryptography;
using TLS;

/// <summary>
/// Throughput / latency / allocation benchmarks for Open-TLS1.3.
///
/// Run: <c>dotnet run -c Release --project Tests bench</c>.
///
/// What's measured per row:
/// <list type="bullet">
///   <item><b>AEAD</b>: throughput (MB/s) + bytes allocated per Encrypt call.</item>
///   <item><b>Handshake</b>: latency (ms) + throughput (hs/s) + bytes allocated per
///     full handshake (client+server in the same process).</item>
/// </list>
///
/// Allocation is captured via <see cref="GC.GetTotalAllocatedBytes"/> (precise=true),
/// which counts heap allocations across all threads since process start — perfect for
/// "what did this loop cost the GC" measurements when bracketed by a full collection.
/// </summary>
public static class Benchmark
{
    // Iteration counts tuned so each row takes roughly 1-3 seconds:
    // AEAD does ~256 MB at 200-300 MB/s for AES-GCM, slower for managed ciphers.
    // Handshake does ~100 full TLS 1.3 exchanges on loopback.
    private const int AeadWarmupIters = 256;
    private const int AeadMeasureIters = 16_000;
    private const int HandshakeWarmupIters = 10;
    private const int HandshakeMeasureIters = 100;

    public static void Run()
    {
        // Print the actual GC mode in use — useful when comparing across machines or
        // when verifying the ServerGarbageCollection csproj switch took effect.
        Console.WriteLine($"== Runtime: .NET {Environment.Version}, " +
                          $"{(System.Runtime.GCSettings.IsServerGC ? "Server" : "Workstation")} GC, " +
                          $"{Environment.ProcessorCount} cores ==");

        Console.WriteLine($"\n== AEAD throughput (encrypt, 16 KiB records, n={AeadMeasureIters:N0}) ==");
        Console.WriteLine($"  {"cipher",-16} {"MB/s",8} {"B/op",8}");
        byte[] data = new byte[16384];
        RandomNumberGenerator.Fill(data);
        byte[] aad = new byte[5];

        AeadBench("AES-256-GCM", new AeadCipher(Key(32), Iv(12), AeadAlgorithm.AesGcm), data, aad);
        AeadBench("MGM-Kuznyechik", new AeadCipher(Key(32), Iv(16), AeadAlgorithm.MgmKuznyechik), data, aad);
        AeadBench("MGM-Magma", new AeadCipher(Key(32), Iv(8), AeadAlgorithm.MgmMagma), data, aad);
        AeadBench("SM4-GCM", new AeadCipher(Key(16), Iv(12), AeadAlgorithm.Sm4Gcm), data, aad);
        AeadBench("SM4-CCM", new AeadCipher(Key(16), Iv(12), AeadAlgorithm.Sm4Ccm), data, aad);

        Console.WriteLine($"\n== Handshake (loopback, n={HandshakeMeasureIters}) ==");
        Console.WriteLine($"  {"profile",-32} {"ms/hs",8} {"hs/s",8} {"KB/hs",8}");
        var ca = CertificateUtils.GenerateCA("Bench CA");
        var ec = CertificateUtils.IssueCertificate("localhost", ca, CertificateProfile.Server);
        var gost = CertificateUtils.IssueGostCertificate("localhost", ca, CertificateProfile.Server, SignatureScheme.Gostr34102012_256a);
        var sm2 = CertificateUtils.IssueSm2Certificate("localhost", ca, CertificateProfile.Server);
        HandshakeBench("default (X25519+AES)", ec, null, null);
        HandshakeBench("GOST (MGM+GC256A+GOST cert)", gost,
            new[] { CipherSuite.TLS_GOSTR341112_256_WITH_KUZNYECHIK_MGM_L }, new[] { NamedGroup.GC256A });
        HandshakeBench("SM (SM4-GCM+curveSM2+SM2 cert)", sm2,
            new[] { CipherSuite.TLS_SM4_GCM_SM3 }, new[] { NamedGroup.Curvesm2 });

        Console.WriteLine($"\n== Bulk transfer (loopback, post-handshake AES-GCM application data) ==");
        Console.WriteLine($"  {"payload",-12} {"records",10} {"MB/s",10} {"KB/MB",10}");
        // After-handshake bulk send: drives the RecordLayer.WriteRecord + ReadRecord pair
        // end-to-end so the per-record allocation savings show up in process-wide bytes.
        BulkTransfer(ec, totalMB: 32);
    }

    private static void AeadBench(string name, AeadCipher c, byte[] data, byte[] aad)
    {
        // Warmup — under AOT there's no JIT to settle, but it still pages in code and
        // gives the GC a steady state before we start measuring.
        for (int i = 0; i < AeadWarmupIters; i++) c.Encrypt(data, aad);

        // Reset the heap so allocations attributed to the measurement window are clean.
        SettleGc();
        long allocBefore = GC.GetTotalAllocatedBytes(precise: true);

        var sw = Stopwatch.StartNew();
        long bytes = 0;
        for (int i = 0; i < AeadMeasureIters; i++) { c.Encrypt(data, aad); bytes += data.Length; }
        sw.Stop();

        long allocAfter = GC.GetTotalAllocatedBytes(precise: true);

        double mbps = bytes / 1e6 / sw.Elapsed.TotalSeconds;
        double bytesPerOp = (allocAfter - allocBefore) / (double)AeadMeasureIters;
        Console.WriteLine($"  {name,-16} {mbps,8:F1} {bytesPerOp,8:F0}");
    }

    private static void HandshakeBench(string name, TlsCertificate cert, CipherSuite[]? suites, NamedGroup[]? groups)
    {
        // Warmup — drains one-time allocations (cipher suite tables, JIT/PGO bookkeeping
        // under non-AOT, BC digest tables, etc.) so they don't pollute the bytes/handshake
        // figure.
        for (int i = 0; i < HandshakeWarmupIters; i++) DoHandshake(cert, suites, groups);

        SettleGc();
        long allocBefore = GC.GetTotalAllocatedBytes(precise: true);

        var sw = Stopwatch.StartNew();
        for (int i = 0; i < HandshakeMeasureIters; i++) DoHandshake(cert, suites, groups);
        sw.Stop();

        long allocAfter = GC.GetTotalAllocatedBytes(precise: true);

        double msPer = sw.Elapsed.TotalMilliseconds / HandshakeMeasureIters;
        double hps = HandshakeMeasureIters / sw.Elapsed.TotalSeconds;
        double kbPer = (allocAfter - allocBefore) / 1024.0 / HandshakeMeasureIters;
        Console.WriteLine($"  {name,-32} {msPer,8:F2} {hps,8:F0} {kbPer,8:F1}");
    }

    /// <summary>
    /// Measure post-handshake bulk-transfer throughput and per-MB allocation. The handshake
    /// runs once (warmup) and is not counted; then the client streams <paramref name="totalMB"/>
    /// of random plaintext through the established encrypted stream, with the server echoing
    /// nothing (just discards). This drives RecordLayer.WriteRecord (client) + ReadRecord
    /// (server) at the 16 KB record size for the entire transfer.
    /// </summary>
    private static void BulkTransfer(TlsCertificate cert, int totalMB)
    {
        var server = new TlsServer(cert);
        server.Listen(0);
        int port = server.LocalPort!.Value;

        long totalBytes = (long)totalMB * 1024 * 1024;
        // Server: accept once, drain the stream into the void.
        var srv = Task.Run(() =>
        {
            try
            {
                using var s = server.Accept();
                byte[] buf = new byte[16 * 1024];
                long read = 0;
                while (read < totalBytes)
                {
                    int n = s.Read(buf, 0, buf.Length);
                    if (n <= 0) break;
                    read += n;
                }
            }
            catch { }
        });

        var c = new TlsClient { HandshakeTimeoutMs = 12000 };
        using var st = c.Connect("127.0.0.1", port);

        byte[] payload = new byte[16 * 1024];
        RandomNumberGenerator.Fill(payload);
        // Measurement starts after the handshake is fully established and one warmup
        // record has flowed (so any one-time cipher-instance allocs are paid).
        st.Write(payload, 0, payload.Length);

        SettleGc();
        long allocBefore = GC.GetTotalAllocatedBytes(precise: true);
        var sw = Stopwatch.StartNew();
        long sent = payload.Length; // count the warmup record toward bytes transferred
        while (sent < totalBytes)
        {
            int chunk = (int)Math.Min(payload.Length, totalBytes - sent);
            st.Write(payload, 0, chunk);
            sent += chunk;
        }
        sw.Stop();
        long allocAfter = GC.GetTotalAllocatedBytes(precise: true);

        st.Dispose();
        srv.Wait(30_000);
        server.Stop();

        long records = (sent + payload.Length - 1) / payload.Length;
        double mbps = sent / 1e6 / sw.Elapsed.TotalSeconds;
        double kbPerMB = (allocAfter - allocBefore) / 1024.0 / (sent / 1_048_576.0);
        Console.WriteLine($"  {payload.Length / 1024 + " KB",-12} {records,10} {mbps,10:F1} {kbPerMB,10:F1}");
    }

    private static void DoHandshake(TlsCertificate cert, CipherSuite[]? suites, NamedGroup[]? groups)
    {
        var server = new TlsServer(cert);
        // Bind port 0 → OS assigns a free port. The static-counter scheme used previously
        // collides with Windows reserved port ranges (Hyper-V dynamic excluded ranges)
        // around port 23000+, raising WSAEACCES randomly. Letting the OS pick avoids it.
        server.Listen(0);
        int port = server.LocalPort!.Value;
        var srv = Task.Run(() => { try { using var s = server.Accept(); var b = new byte[64]; int n = s.Read(b); s.Write(b, 0, n); } catch { } });
        var c = new TlsClient { HandshakeTimeoutMs = 12000 };
        if (suites != null) c.CipherSuites = suites;
        if (groups != null) c.NamedGroups = groups;
        // Use the IPv4 loopback literal, not "localhost". On Windows "localhost" resolves
        // to ::1 first; the server binds IPAddress.Any (v4-only), so the client wastes
        // ~2s on IPv6 SYN→RST backoff before falling back to 127.0.0.1. That OS delay
        // would otherwise swamp the actual handshake measurement.
        using (var st = c.Connect("127.0.0.1", port))
        {
            st.Write(new byte[] { 1, 2, 3 });
            var b = new byte[64]; st.Read(b);
        }
        srv.Wait(6000); server.Stop();
    }

    /// <summary>Force a full GC settle before allocation-sensitive measurement.</summary>
    private static void SettleGc()
    {
        GC.Collect();
        GC.WaitForPendingFinalizers();
        GC.Collect();
    }

    private static byte[] Key(int n) { var k = new byte[n]; RandomNumberGenerator.Fill(k); return k; }
    private static byte[] Iv(int n) { var v = new byte[n]; RandomNumberGenerator.Fill(v); return v; }
}
