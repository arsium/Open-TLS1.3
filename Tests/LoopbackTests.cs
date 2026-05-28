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

        Section("Record layer: malformed records rejected cleanly (RFC 8446 §5.2)");
        MalformedRecordRejection();

        Section("HandshakeMessages: build → parse round-trips (wire-format check)");
        HandshakeMessageRoundTrips();
    }

    // Build → parse round-trips for the handshake messages NOT exercised by the loopback
    // suite (PSK resumption, HelloRetryRequest, NewSessionTicket, 0-RTT, ServerHello-with-PSK).
    // These builders were migrated from MemoryStream to ArrayBufferWriter this session; a
    // length-prefix off-by-one would silently produce wrong wire bytes that no other test
    // would catch. Round-tripping through the parsers validates the framing end-to-end.
    private static void HandshakeMessageRoundTrips()
    {
        // --- NewSessionTicket (RFC 8446 §4.6.1) ---
        {
            byte[] nonce = { 0x11, 0x22, 0x33, 0x44 };
            byte[] ticket = new byte[64];
            for (int i = 0; i < ticket.Length; i++) ticket[i] = (byte)(i * 7);
            byte[] msg = HandshakeMessages.BuildNewSessionTicket(7200, 0xAABBCCDD, nonce, ticket, 16384);
            var (hsType, body) = HandshakeMessages.Unframe(msg);
            Check("NST framing type", hsType == HandshakeType.NewSessionTicket);
            var p = HandshakeMessages.ParseNewSessionTicket(body);
            Check("NST lifetime", p.Lifetime == 7200);
            Check("NST age_add", p.AgeAdd == 0xAABBCCDD);
            Check("NST nonce", Eqb(p.Nonce, nonce));
            Check("NST ticket", Eqb(p.Ticket, ticket));
            Check("NST max_early_data", p.MaxEarlyDataSize == 16384);
        }

        // --- pre_shared_key extension (RFC 8446 §4.2.11) ---
        {
            byte[] identity = new byte[40];
            for (int i = 0; i < identity.Length; i++) identity[i] = (byte)(0xC0 + i);
            byte[] binder = new byte[48];
            for (int i = 0; i < binder.Length; i++) binder[i] = (byte)(i + 1);
            byte[] ext = HandshakeMessages.BuildPreSharedKeyExtension(identity, 0x11223344, binder);
            var (ids, ages, binders) = HandshakeMessages.ParsePreSharedKeyExtension(ext);
            Check("PSK ext identity count", ids.Length == 1);
            Check("PSK ext identity", ids.Length == 1 && Eqb(ids[0], identity));
            Check("PSK ext obfuscated_age", ages.Length == 1 && ages[0] == 0x11223344);
            Check("PSK ext binder", binders.Length == 1 && Eqb(binders[0], binder));
        }

        // --- HelloRetryRequest (RFC 8446 §4.1.4, encoded as ServerHello + sentinel) ---
        {
            byte[] sessionId = new byte[32];
            for (int i = 0; i < 32; i++) sessionId[i] = (byte)i;
            byte[] msg = HandshakeMessages.BuildHelloRetryRequest(sessionId,
                CipherSuite.TLS_AES_256_GCM_SHA384, NamedGroup.X25519);
            var (_, body) = HandshakeMessages.Unframe(msg);
            var sh = HandshakeMessages.ParseServerHello(body);
            Check("HRR detected", sh.IsHelloRetryRequest);
            Check("HRR suite", sh.CipherSuite == CipherSuite.TLS_AES_256_GCM_SHA384);
            Check("HRR requested group", sh.KeyShareGroup == NamedGroup.X25519);
            Check("HRR session_id echoed", Eqb(sh.SessionId, sessionId));
        }

        // --- ClientHello with PSK + early_data (RFC 8446 §4.1.2 / §4.2.10 / §4.2.11) ---
        {
            byte[] clientRandom = new byte[32];
            for (int i = 0; i < 32; i++) clientRandom[i] = (byte)(0x80 + i);
            byte[] sessionId = new byte[32];
            var suites = new[] { CipherSuite.TLS_AES_256_GCM_SHA384 };
            var keyShares = new (NamedGroup, byte[])[] { (NamedGroup.X25519, new byte[32]) };
            byte[] pskIdentity = new byte[20];
            for (int i = 0; i < 20; i++) pskIdentity[i] = (byte)(0x40 + i);
            byte[] binderPlaceholder = new byte[48];
            byte[] msg = HandshakeMessages.BuildClientHelloWithPsk(clientRandom, sessionId, suites, keyShares,
                pskIdentity, 999999, binderPlaceholder, offerEarlyData: true, serverName: "example.test");
            var (_, body) = HandshakeMessages.Unframe(msg);
            var ch = HandshakeMessages.ParseClientHello(body);
            Check("CH-PSK client_random", Eqb(ch.ClientRandom, clientRandom));
            // GREASE cipher suite is prepended by the builder, so look for membership.
            Check("CH-PSK suite present", Array.IndexOf(ch.CipherSuites, CipherSuite.TLS_AES_256_GCM_SHA384) >= 0);
            Check("CH-PSK offers early_data", ch.OffersEarlyData);
            Check("CH-PSK SNI", ch.ServerName == "example.test");
            Check("CH-PSK has pre_shared_key", ch.PreSharedKeyData != null);
            if (ch.PreSharedKeyData != null)
            {
                var (ids, ages, _) = HandshakeMessages.ParsePreSharedKeyExtension(ch.PreSharedKeyData);
                Check("CH-PSK identity round-trips", ids.Length == 1 && Eqb(ids[0], pskIdentity));
                Check("CH-PSK age round-trips", ages.Length == 1 && ages[0] == 999999);
            }
        }

        // --- ServerHello with PSK (RFC 8446 §4.1.3 + selected pre_shared_key) ---
        {
            byte[] serverRandom = new byte[32];
            for (int i = 0; i < 32; i++) serverRandom[i] = (byte)(0x10 + i);
            byte[] sessionId = new byte[16];
            byte[] pubKey = new byte[32];
            byte[] msg = HandshakeMessages.BuildServerHelloWithPsk(serverRandom, sessionId,
                CipherSuite.TLS_AES_256_GCM_SHA384, NamedGroup.X25519, pubKey, selectedPskIndex: 0);
            var (_, body) = HandshakeMessages.Unframe(msg);
            var sh = HandshakeMessages.ParseServerHello(body);
            Check("SH-PSK not HRR", !sh.IsHelloRetryRequest);
            Check("SH-PSK suite", sh.CipherSuite == CipherSuite.TLS_AES_256_GCM_SHA384);
            Check("SH-PSK selected_identity", sh.SelectedPskIndex == 0);
            Check("SH-PSK key_share group", sh.KeyShareGroup == NamedGroup.X25519);
        }

        // --- EndOfEarlyData (RFC 8446 §4.5) ---
        {
            byte[] msg = HandshakeMessages.BuildEndOfEarlyData();
            var (hsType, body) = HandshakeMessages.Unframe(msg);
            Check("EndOfEarlyData type", hsType == HandshakeType.EndOfEarlyData);
            Check("EndOfEarlyData empty body", body.Length == 0);
        }
    }

    // Regression guard: a peer sending an encrypted ApplicationData record whose length
    // field is below the AEAD tag length must be rejected with a TlsException (mapped to a
    // bad_record_mac alert), NOT a raw ArgumentOutOfRangeException from a negative-length
    // Span.Slice / ArrayPool.Rent. Covers every record read path (legacy + direct-decrypt,
    // sync + async).
    private static void MalformedRecordRejection()
    {
        // ApplicationData(0x17) ‖ version 0x0303 ‖ length=5 ‖ 5 payload bytes.
        // 5 < 16 (AES-GCM tag) ⇒ ctLen = -11 would underflow the buffer math.
        static System.IO.MemoryStream CraftShortRecord()
        {
            var ms = new System.IO.MemoryStream();
            ms.Write(new byte[] { 0x17, 0x03, 0x03, 0x00, 0x05, 0, 0, 0, 0, 0 }, 0, 10);
            ms.Position = 0;
            return ms;
        }

        static AeadCipher NewCipher() => new AeadCipher(new byte[32], new byte[12], AeadAlgorithm.AesGcm);

        // Legacy sync ReadRecord
        {
            var rl = new RecordLayer(CraftShortRecord());
            rl.SetReadCipher(NewCipher());
            bool clean = false;
            try { rl.ReadRecord(); }
            catch (TlsException) { clean = true; }
            catch { /* any other exception type = the bug we fixed */ }
            Check("short record → TlsException (ReadRecord)", clean);
        }

        // Direct-decrypt sync ReadRecordInto
        {
            var rl = new RecordLayer(CraftShortRecord());
            rl.SetReadCipher(NewCipher());
            bool clean = false;
            try { rl.ReadRecordInto(new byte[16384]); }
            catch (TlsException) { clean = true; }
            catch { }
            Check("short record → TlsException (ReadRecordInto)", clean);
        }

        // Legacy async ReadRecordAsync
        {
            var rl = new RecordLayer(CraftShortRecord());
            rl.SetReadCipher(NewCipher());
            bool clean = false;
            try { rl.ReadRecordAsync().GetAwaiter().GetResult(); }
            catch (TlsException) { clean = true; }
            catch { }
            Check("short record → TlsException (ReadRecordAsync)", clean);
        }

        // Direct-decrypt async ReadRecordIntoAsync
        {
            var rl = new RecordLayer(CraftShortRecord());
            rl.SetReadCipher(NewCipher());
            bool clean = false;
            try { rl.ReadRecordIntoAsync(new byte[16384]).GetAwaiter().GetResult(); }
            catch (TlsException) { clean = true; }
            catch { }
            Check("short record → TlsException (ReadRecordIntoAsync)", clean);
        }

        // Trial-decrypt paths must NOT throw on a short record — they return null
        // (failed trial decryption, used for 0-RTT skip per RFC 8446 §4.2.10).
        {
            var rl = new RecordLayer(CraftShortRecord());
            rl.SetReadCipher(NewCipher());
            bool nullResult = false;
            try { nullResult = rl.TryReadRecord() == null; }
            catch { /* should not throw */ }
            Check("short record → null (TryReadRecord, no throw)", nullResult);
        }
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
