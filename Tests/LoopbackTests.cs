namespace Tests;

using System.Text;
using TLS;
using static Tests.T;

/// <summary>End-to-end handshake + data tests over a loopback TCP connection.</summary>
public static class LoopbackTests
{
    private static int _port = 21000;

    public static void Run()
    {
        var ca = CertificateUtils.GenerateCA("Test Suite CA");
        var ecCert = CertificateUtils.IssueCertificate("localhost", ca, CertificateProfile.Server);
        var gostCert = CertificateUtils.IssueGostCertificate("localhost", ca, CertificateProfile.Server, SignatureScheme.Gostr34102012_256a);
        var sm2Cert = CertificateUtils.IssueSm2Certificate("localhost", ca, CertificateProfile.Server);

        Section("Loopback: default TLS 1.3 (X25519 + AES-GCM)");
        Handshake("AES-256-GCM small", ecCert, null, null, 30);
        Handshake("AES-256-GCM large (40KB)", ecCert, null, null, 40000);
        Handshake("AES-128-GCM", ecCert, new[] { CipherSuite.TLS_AES_128_GCM_SHA256 }, null, 256);

        Section("Loopback: GOST (RFC 9367) — full national stack");
        foreach (var suite in new[] {
            CipherSuite.TLS_GOSTR341112_256_WITH_KUZNYECHIK_MGM_L,
            CipherSuite.TLS_GOSTR341112_256_WITH_MAGMA_MGM_L,
            CipherSuite.TLS_GOSTR341112_256_WITH_KUZNYECHIK_MGM_S,
            CipherSuite.TLS_GOSTR341112_256_WITH_MAGMA_MGM_S })
            Handshake($"{suite} + GC256A + GOST cert", gostCert, new[] { suite }, new[] { NamedGroup.GC256A }, 1024);
        Handshake("GOST + GC512A key exchange", gostCert,
            new[] { CipherSuite.TLS_GOSTR341112_256_WITH_KUZNYECHIK_MGM_L }, new[] { NamedGroup.GC512A }, 40000);

        Section("Loopback: Chinese SM (RFC 8998) — full national stack");
        Handshake("SM4-GCM-SM3 + curveSM2 + SM2 cert", sm2Cert,
            new[] { CipherSuite.TLS_SM4_GCM_SM3 }, new[] { NamedGroup.Curvesm2 }, 40000);
        Handshake("SM4-CCM-SM3 + curveSM2 + SM2 cert", sm2Cert,
            new[] { CipherSuite.TLS_SM4_CCM_SM3 }, new[] { NamedGroup.Curvesm2 }, 1024);

        Section("Loopback: mTLS (client certificate)");
        MutualTls(ca, ecCert);

        Section("Loopback: RFC 8879 certificate compression (BrotliSharpLib + ZstdSharp)");
        HandshakeWithCertCompression("compressed cert handshake", ecCert);
    }

    // Exercises the full RFC 8879 cert compression path through the handshake:
    // server enables compression, the client advertises brotli+zstd, and the leaf cert
    // travels as a CompressedCertificate message instead of a plain Certificate. This is
    // the only test that actually invokes BrotliSharpLib end-to-end in the TLS layer.
    private static void HandshakeWithCertCompression(string name, TlsCertificate cert)
    {
        int port = ++_port;
        var server = new TlsServer(cert) { UseCertificateCompression = true };
        server.Listen(port);
        var srv = Task.Run(() =>
        {
            try
            {
                using var s = server.Accept();
                var b = new byte[1024];
                int n = s.Read(b);
                s.Write(b, 0, n);
                Thread.Sleep(100);
            }
            catch { }
        });
        try
        {
            var c = new TlsClient { HandshakeTimeoutMs = 12000 };
            using var st = c.Connect("localhost", port);
            var msg = Encoding.ASCII.GetBytes("brotli-compressed-cert-test");
            st.Write(msg);
            var buf = new byte[1024];
            int got = st.Read(buf);
            Check(name, got == msg.Length && buf.AsSpan(0, got).SequenceEqual(msg));
        }
        catch (Exception e) { Check($"{name} [{e.GetType().Name}: {e.Message}]", false); }
        finally { srv.Wait(6000); server.Stop(); }
    }

    private static void Handshake(string name, TlsCertificate serverCert,
        CipherSuite[]? suites, NamedGroup[]? groups, int msgLen)
    {
        int port = ++_port;
        var server = new TlsServer(serverCert);
        server.Listen(port);
        var srv = Task.Run(() =>
        {
            try
            {
                using var s = server.Accept();
                var b = new byte[msgLen + 4096];
                int got = 0;
                while (got < msgLen) { int n = s.Read(b, got, b.Length - got); if (n <= 0) break; got += n; }
                s.Write(b, 0, got);
                Thread.Sleep(100);
            }
            catch { /* surfaced via client failure */ }
        });

        try
        {
            var c = new TlsClient { HandshakeTimeoutMs = 12000 };
            if (suites != null) c.CipherSuites = suites;
            if (groups != null) c.NamedGroups = groups;
            using var st = c.Connect("localhost", port);
            byte[] msg = Encoding.ASCII.GetBytes(new string('Z', msgLen));
            st.Write(msg);
            var buf = new byte[msgLen + 4096];
            int got = 0;
            while (got < msgLen) { int n = st.Read(buf, got, buf.Length - got); if (n <= 0) break; got += n; }
            Check(name, got == msgLen && buf.AsSpan(0, got).SequenceEqual(msg));
        }
        catch (Exception e) { Check($"{name} [{e.GetType().Name}: {e.Message}]", false); }
        finally { srv.Wait(6000); server.Stop(); }
    }

    private static void MutualTls(TlsCertificate ca, TlsCertificate serverCert)
    {
        int port = ++_port;
        var clientCert = CertificateUtils.IssueCertificate("test-client", ca, CertificateProfile.Client);
        var server = new TlsServer(serverCert) { RequireClientCertificate = true, CaCertificate = ca };
        server.Listen(port);
        string? seenCn = null;
        var srv = Task.Run(() =>
        {
            try
            {
                using var s = server.Accept();
                if (s.PeerCertificate != null) seenCn = CertificateUtils.ExtractCommonName(s.PeerCertificate);
                var b = new byte[256]; int n = s.Read(b); s.Write(b, 0, n); Thread.Sleep(100);
            }
            catch { }
        });
        try
        {
            var c = new TlsClient { HandshakeTimeoutMs = 12000 };
            using var st = c.Connect("localhost", port, clientCert);
            var msg = Encoding.ASCII.GetBytes("mtls-hello");
            st.Write(msg);
            var buf = new byte[256]; int n = st.Read(buf);
            Check("mTLS handshake + client cert seen",
                buf.AsSpan(0, n).SequenceEqual(msg) && seenCn == "test-client");
        }
        catch (Exception e) { Check($"mTLS [{e.GetType().Name}: {e.Message}]", false); }
        finally { srv.Wait(6000); server.Stop(); }
    }
}
