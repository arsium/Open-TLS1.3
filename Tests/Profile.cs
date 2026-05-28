namespace Tests;

using System.Net;
using System.Net.Sockets;
using TLS;

/// <summary>
/// Single-handshake allocation profile with phase breakdown. Use to answer
/// "where do the ~10 MB per handshake go?" — total bench gives one number,
/// this gives per-phase deltas.
///
/// Run: <c>dotnet run -c Release --project Tests profile</c>.
///
/// Methodology:
///   - Warmup with N handshakes per cert profile so one-time costs (cert generators,
///     BC type initialisers, cipher tables) are paid before measurement.
///   - SettleGc() once at the start of each profile to flush any pending GC work
///     that would otherwise allocate during measurement.
///   - GC.GetTotalAllocatedBytes(precise=true) snapshot at each phase boundary.
///     Process-wide counter, so server-side allocations are attributed to whichever
///     client-side phase they happen to overlap with. Total per-handshake is exact;
///     per-phase split is approximate at phase boundaries that span both sides.
///   - Plain-TCP profile runs first as a baseline so we can subtract socket overhead
///     and read off TLS-specific allocation.
/// </summary>
public static class Profile
{
    private const int WarmupIters = 10;

    public static void Run()
    {
        Console.WriteLine($"== Runtime: .NET {Environment.Version}, " +
                          $"{(System.Runtime.GCSettings.IsServerGC ? "Server" : "Workstation")} GC, " +
                          $"{Environment.ProcessorCount} cores ==");
        Console.WriteLine("== Single-handshake allocation profile ==\n");

        var ca = CertificateUtils.GenerateCA("Profile CA");
        var ec = CertificateUtils.IssueCertificate("localhost", ca, CertificateProfile.Server);
        var gost = CertificateUtils.IssueGostCertificate("localhost", ca, CertificateProfile.Server, SignatureScheme.Gostr34102012_256a);
        var sm2 = CertificateUtils.IssueSm2Certificate("localhost", ca, CertificateProfile.Server);

        // Warm everything: each cert profile runs WarmupIters times before we measure
        // anything. This pays one-time costs (BC class ctors, certificate generators,
        // TlsConnection static state) outside the measurement window.
        for (int i = 0; i < WarmupIters; i++)
        {
            DoTlsHandshakeQuiet(ec, null, null);
            DoTlsHandshakeQuiet(gost, new[] { CipherSuite.TLS_GOSTR341112_256_WITH_KUZNYECHIK_MGM_L }, new[] { NamedGroup.GC256A });
            DoTlsHandshakeQuiet(sm2, new[] { CipherSuite.TLS_SM4_GCM_SM3 }, new[] { NamedGroup.Curvesm2 });
            DoPlainTcpQuiet();
        }

        ProfilePlainTcp();
        ProfileTls("default (X25519+AES+RSA cert)", ec, null, null);
        ProfileTls("GOST (MGM+GC256A+GOST cert)", gost,
            new[] { CipherSuite.TLS_GOSTR341112_256_WITH_KUZNYECHIK_MGM_L }, new[] { NamedGroup.GC256A });
        ProfileTls("SM (SM4-GCM+curveSM2+SM2 cert)", sm2,
            new[] { CipherSuite.TLS_SM4_GCM_SM3 }, new[] { NamedGroup.Curvesm2 });

        // Intra-handshake phase breakdown: subscribe to the TlsConnection phase hook and
        // record allocation snapshots at each named checkpoint. Both client AND server
        // call into the same hook; markers are prefixed "client/" or "server/" to keep
        // them disentangled in the output.
        Console.WriteLine("== Intra-handshake phase breakdown ==");
        ProfileIntraHandshake("default (X25519+AES+RSA cert)", ec, null, null);
        ProfileIntraHandshake("GOST (MGM+GC256A+GOST cert)", gost,
            new[] { CipherSuite.TLS_GOSTR341112_256_WITH_KUZNYECHIK_MGM_L }, new[] { NamedGroup.GC256A });
        ProfileIntraHandshake("SM (SM4-GCM+curveSM2+SM2 cert)", sm2,
            new[] { CipherSuite.TLS_SM4_GCM_SM3 }, new[] { NamedGroup.Curvesm2 });
    }

    private static void ProfileIntraHandshake(string name, TlsCertificate cert, CipherSuite[]? suites, NamedGroup[]? groups)
    {
        Console.WriteLine($"\n-- {name} --");
        // (phase, alloc_bytes_at_capture_time)
        var phases = new List<(string phase, long alloc)>();
        TLS.HandshakePhaseHook.Hook = phase =>
        {
            phases.Add((phase, GC.GetTotalAllocatedBytes(precise: true)));
        };
        try
        {
            SettleGc();
            long t0 = GC.GetTotalAllocatedBytes(precise: true);
            phases.Add(("(handshake start)", t0));
            DoTlsHandshakeQuiet(cert, suites, groups);
            long tEnd = GC.GetTotalAllocatedBytes(precise: true);
            phases.Add(("(handshake end)", tEnd));
        }
        finally
        {
            TLS.HandshakePhaseHook.Hook = null;
        }

        // Print deltas in order. Client and server may interleave on different threads —
        // the deltas reflect total process allocation between consecutive markers, NOT
        // pure single-side cost.
        Console.WriteLine($"  {"phase",-44} {"KB delta",10}  cumulative");
        long prev = phases[0].alloc;
        long start = phases[0].alloc;
        for (int i = 1; i < phases.Count; i++)
        {
            long cur = phases[i].alloc;
            long delta = cur - prev;
            long cum = cur - start;
            Console.WriteLine($"  {phases[i].phase,-44} {delta / 1024.0,10:F1}  {cum / 1024.0,10:F1}");
            prev = cur;
        }
    }

    private static void ProfilePlainTcp()
    {
        Console.WriteLine("-- plain TCP (no TLS — baseline for socket/stream overhead) --");
        SettleGc();
        long t0 = GC.GetTotalAllocatedBytes(precise: true);

        var listener = new TcpListener(IPAddress.Any, 0);
        listener.Start();
        int port = ((IPEndPoint)listener.LocalEndpoint).Port;
        long t1 = GC.GetTotalAllocatedBytes(precise: true);
        Phase("listener setup", t0, t1);

        Task srvTask = Task.Run(() =>
        {
            try
            {
                using var s = listener.AcceptTcpClient();
                using var ns = s.GetStream();
                var b = new byte[64];
                int n = ns.Read(b);
                ns.Write(b, 0, n);
            }
            catch { }
        });
        long t2 = GC.GetTotalAllocatedBytes(precise: true);
        Phase("server task spawn", t1, t2);

        var c = new TcpClient { NoDelay = true };
        c.Connect("127.0.0.1", port);
        using var stream = c.GetStream();
        long t3 = GC.GetTotalAllocatedBytes(precise: true);
        Phase("Connect (TCP only)", t2, t3);

        stream.Write(new byte[] { 1, 2, 3 });
        var rb = new byte[64];
        stream.Read(rb);
        long t4 = GC.GetTotalAllocatedBytes(precise: true);
        Phase("data exchange (3B+64B echo)", t3, t4);

        c.Dispose();
        srvTask.Wait(6000);
        listener.Stop();
        long t5 = GC.GetTotalAllocatedBytes(precise: true);
        Phase("teardown", t4, t5);

        Phase("TOTAL", t0, t5);
        Console.WriteLine();
    }

    private static void ProfileTls(string name, TlsCertificate cert, CipherSuite[]? suites, NamedGroup[]? groups)
    {
        Console.WriteLine($"-- {name} --");
        SettleGc();
        long t0 = GC.GetTotalAllocatedBytes(precise: true);

        var server = new TlsServer(cert);
        server.Listen(0);
        int port = server.LocalPort!.Value;
        long t1 = GC.GetTotalAllocatedBytes(precise: true);
        Phase("server setup (TlsServer+Listen)", t0, t1);

        // Server task runs concurrently with the client. Its allocations are folded
        // into whichever client-side phase happens to overlap (mostly Connect).
        Task srvTask = Task.Run(() =>
        {
            try
            {
                using var s = server.Accept();
                var b = new byte[64];
                int n = s.Read(b);
                s.Write(b, 0, n);
            }
            catch { }
        });
        long t2 = GC.GetTotalAllocatedBytes(precise: true);
        Phase("server task spawn", t1, t2);

        var c = new TlsClient { HandshakeTimeoutMs = 12000 };
        if (suites != null) c.CipherSuites = suites;
        if (groups != null) c.NamedGroups = groups;
        long t3 = GC.GetTotalAllocatedBytes(precise: true);
        Phase("client setup (TlsClient ctor)", t2, t3);

        using var st = c.Connect("127.0.0.1", port);
        long t4 = GC.GetTotalAllocatedBytes(precise: true);
        Phase("Connect (TCP + full TLS handshake)", t3, t4);

        st.Write(new byte[] { 1, 2, 3 });
        var b = new byte[64];
        st.Read(b);
        long t5 = GC.GetTotalAllocatedBytes(precise: true);
        Phase("data exchange (3B+64B echo, AEAD)", t4, t5);

        srvTask.Wait(6000);
        server.Stop();
        long t6 = GC.GetTotalAllocatedBytes(precise: true);
        Phase("teardown (Stop + srv.Wait)", t5, t6);

        Phase("TOTAL", t0, t6);
        Console.WriteLine();
    }

    private static void Phase(string label, long before, long after)
    {
        long delta = after - before;
        double kb = delta / 1024.0;
        Console.WriteLine($"  {label,-40} {kb,10:F1} KB");
    }

    private static void SettleGc()
    {
        GC.Collect();
        GC.WaitForPendingFinalizers();
        GC.Collect();
    }

    private static void DoTlsHandshakeQuiet(TlsCertificate cert, CipherSuite[]? suites, NamedGroup[]? groups)
    {
        var server = new TlsServer(cert);
        server.Listen(0);
        int port = server.LocalPort!.Value;
        var srv = Task.Run(() =>
        {
            try
            {
                using var s = server.Accept();
                var b = new byte[64];
                int n = s.Read(b);
                s.Write(b, 0, n);
            }
            catch { }
        });
        var c = new TlsClient { HandshakeTimeoutMs = 12000 };
        if (suites != null) c.CipherSuites = suites;
        if (groups != null) c.NamedGroups = groups;
        using (var st = c.Connect("127.0.0.1", port))
        {
            st.Write(new byte[] { 1, 2, 3 });
            var b = new byte[64];
            st.Read(b);
        }
        srv.Wait(6000);
        server.Stop();
    }

    private static void DoPlainTcpQuiet()
    {
        var listener = new TcpListener(IPAddress.Any, 0);
        listener.Start();
        int port = ((IPEndPoint)listener.LocalEndpoint).Port;
        var srv = Task.Run(() =>
        {
            try
            {
                using var s = listener.AcceptTcpClient();
                using var ns = s.GetStream();
                var b = new byte[64];
                int n = ns.Read(b);
                ns.Write(b, 0, n);
            }
            catch { }
        });
        var c = new TcpClient { NoDelay = true };
        c.Connect("127.0.0.1", port);
        using var stream = c.GetStream();
        stream.Write(new byte[] { 1, 2, 3 });
        var rb = new byte[64];
        stream.Read(rb);
        c.Dispose();
        srv.Wait(6000);
        listener.Stop();
    }
}
