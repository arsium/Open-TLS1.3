namespace Tests;

using System.Net.Sockets;
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
        var mldsaCert = CertificateUtils.IssueMlDsaCertificate("localhost", ca, CertificateProfile.Server, SignatureScheme.MlDsa65);

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

        Section("Loopback: AEGIS (draft-denis-tls-aegis-06)");
        Handshake("AEGIS-128L-SHA256 small", ecCert, new[] { CipherSuite.TLS_AEGIS_128L_SHA256 }, null, 256);
        Handshake("AEGIS-128L-SHA256 large (40KB)", ecCert, new[] { CipherSuite.TLS_AEGIS_128L_SHA256 }, null, 40000);
        Handshake("AEGIS-256-SHA512 small", ecCert, new[] { CipherSuite.TLS_AEGIS_256_SHA512 }, null, 256);
        Handshake("AEGIS-256-SHA512 large (40KB)", ecCert, new[] { CipherSuite.TLS_AEGIS_256_SHA512 }, null, 40000);

        Section("Loopback: ML-DSA post-quantum certificate (FIPS 204 / draft-ietf-tls-mldsa)");
        Handshake("ML-DSA-65 cert + AES-256-GCM", mldsaCert, null, null, 1024);
        Handshake("ML-DSA-44 cert + ChaCha20", CertificateUtils.IssueMlDsaCertificate("localhost", ca, CertificateProfile.Server, SignatureScheme.MlDsa44),
            new[] { CipherSuite.TLS_CHACHA20_POLY1305_SHA256 }, null, 256);
        Handshake("ML-DSA-87 cert (largest) + AES-256-GCM", CertificateUtils.IssueMlDsaCertificate("localhost", ca, CertificateProfile.Server, SignatureScheme.MlDsa87),
            null, null, 4096);
        Handshake("ML-DSA-65 + X25519MLKEM768 (fully post-quantum handshake)", mldsaCert, null, new[] { NamedGroup.X25519MLKEM768 }, 1024);
        MlDsaChain();

        Section("Loopback: certificate + external PSK (draft-ietf-tls-8773bis, Internet-Draft)");
        CertWithExternalPsk("cert + extern PSK (EC cert)", ca, ecCert, useAsync: false);
        CertWithExternalPsk("cert + extern PSK (EC cert, async)", ca, ecCert, useAsync: true);
        CertWithExternalPsk("cert + extern PSK (ML-DSA-65 cert — PQ cert + PSK)", ca, mldsaCert, useAsync: false);

        Section("Loopback: configurable negotiation (server allow-lists + client sig-alg override)");
        ConfigurableNegotiation(ca, ecCert);

        Section("Loopback: opt-in features (ALPN, OCSP, padding, KeyUpdate, exporter, channel binding, RFC 9261, post-handshake auth)");
        OptInFeatures(ca, ecCert);

        Section("Loopback: mTLS (client certificate)");
        MutualTls(ca, ecCert);
        MutualTls(ca, ecCert, useCompression: true);

        Section("Loopback: RFC 8879 certificate compression (BrotliSharpLib + ZstdSharp)");
        HandshakeWithCertCompression("compressed cert handshake", ecCert);

        Section("Loopback: hybrid post-quantum key exchange (draft-ietf-tls-ecdhe-mlkem)");
        Handshake("X25519MLKEM768 hybrid + AES-256-GCM", ecCert, null, new[] { NamedGroup.X25519MLKEM768 }, 1024);
        Handshake("X25519MLKEM768 hybrid large (40KB)", ecCert, null, new[] { NamedGroup.X25519MLKEM768 }, 40000);
        Handshake("SecP256r1MLKEM768 hybrid (ECDH-first) + AES-256-GCM", ecCert, null, new[] { NamedGroup.SecP256r1MLKEM768 }, 1024);
        Handshake("SecP256r1MLKEM768 hybrid large (40KB)", ecCert, null, new[] { NamedGroup.SecP256r1MLKEM768 }, 40000);
        Handshake("SecP384r1MLKEM1024 hybrid (P-384 + ML-KEM-1024) + AES-256-GCM", ecCert, null, new[] { NamedGroup.SecP384r1MLKEM1024 }, 1024);
        Handshake("SecP384r1MLKEM1024 hybrid large (40KB)", ecCert, null, new[] { NamedGroup.SecP384r1MLKEM1024 }, 40000);
        MlKemRoundTrip();

        Section("Loopback: async handshake paths (ConnectAsync / AcceptAsync)");
        AsyncHandshake("async X25519 default", ecCert, null, 1024);
        AsyncHandshake("async X25519MLKEM768 hybrid", ecCert, new[] { NamedGroup.X25519MLKEM768 }, 4096);
        AsyncHandshake("async SecP256r1MLKEM768 hybrid", ecCert, new[] { NamedGroup.SecP256r1MLKEM768 }, 4096);

        Section("Loopback: session resumption + 0-RTT early data (RFC 8446 §4.6.1 / §4.2.10 / §8)");
        ResumptionAndEarlyData("resumption + 0-RTT", ecCert);

        EchHandshake(ecCert);
        ForceHrrHandshake(ecCert);

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

    // Fully post-quantum certificate CHAIN: an ML-DSA root CA signs an ML-DSA leaf, and the client
    // validates the chain against the ML-DSA root — so both the chain signature (VerifyChain) and the
    // leaf authentication (CertificateVerify) are ML-DSA, with no classical signature in the cert path.
    private static void MlDsaChain()
    {
        var pqRoot = CertificateUtils.GenerateMlDsaCA("Open-TLS1.3 PQ Root CA", SignatureScheme.MlDsa65);
        var leaf = CertificateUtils.IssueMlDsaCertificate("localhost", pqRoot, CertificateProfile.Server, SignatureScheme.MlDsa65);
        Check("ML-DSA chain: leaf verifies against ML-DSA root", CertificateUtils.VerifyChain(leaf, pqRoot));

        int port = ++_port;
        var server = new TlsServer(leaf);
        server.Listen(port);
        var srv = Task.Run(() =>
        {
            try { using var s = server.Accept(); var b = new byte[64]; int n = s.Read(b, 0, b.Length); if (n > 0) s.Write(b, 0, n); }
            catch { /* surfaced via client failure */ }
        });
        try
        {
            var c = new TlsClient { HandshakeTimeoutMs = 12000, CaCertificate = pqRoot };
            using var st = c.Connect("localhost", port);
            st.Write(new byte[] { 1, 2, 3, 4 }, 0, 4);
            var buf = new byte[64];
            Check("ML-DSA chain: handshake + echo (client trusts ML-DSA root)", st.Read(buf, 0, buf.Length) == 4);
        }
        catch (Exception e) { Check($"ML-DSA chain [{e.GetType().Name}: {e.Message}]", false); }
        finally { srv.Wait(6000); server.Stop(); }
    }

    // draft-ietf-tls-8773bis (Internet-Draft): certificate authentication combined with an external PSK.
    // A FULL certificate handshake runs (Certificate + CertificateVerify), but the external PSK is also
    // folded into the key schedule — so the session resists a future break of the certificate's signature
    // algorithm. Exercised over a raw TlsConnection because the high-level TlsClient/TlsServer wrappers do
    // not surface external PSKs. Validates client + server on both the sync and async handshake paths.
    private static void CertWithExternalPsk(string name, TlsCertificate ca, TlsCertificate serverCert, bool useAsync)
    {
        var psk = new ExternalPsk
        {
            Identity = Encoding.ASCII.GetBytes("8773bis-test-identity"),
            Key = new byte[32],
            Suite = CipherSuite.TLS_AES_256_GCM_SHA384,
            MaxEarlyDataSize = 0, // early_data is forbidden alongside tls_cert_with_extern_psk
        };
        for (int i = 0; i < psk.Key.Length; i++) psk.Key[i] = (byte)(i + 1);

        const int msgLen = 96;
        int port = ++_port;
        var listener = new TcpListener(System.Net.IPAddress.Loopback, port);
        listener.Start();

        bool serverMode = false;
        string? serverErr = null;
        var srv = Task.Run(async () =>
        {
            try
            {
                using var tcp = await listener.AcceptTcpClientAsync();
                var stream = tcp.GetStream();
                var conn = new TlsConnection(stream, isServer: true, serverCert);
                conn.ImportExternalPsk(psk);
                if (useAsync) await conn.HandshakeAsServerAsync(default);
                else conn.HandshakeAsServer();
                serverMode = conn.UsedCertWithExternalPsk;

                using var st = new TlsStream(conn, tcp);
                var b = new byte[msgLen + 256];
                int got = 0;
                while (got < msgLen) { int n = st.Read(b, got, b.Length - got); if (n <= 0) break; got += n; }
                st.Write(b, 0, got);
                Thread.Sleep(50);
            }
            catch (Exception e) { serverErr = e.Message; }
        });

        try
        {
            using var tcp = new TcpClient { NoDelay = true };
            tcp.Connect("localhost", port);
            var stream = tcp.GetStream();
            stream.ReadTimeout = 12000;
            var conn = new TlsConnection(stream, isServer: false);
            conn.SetOfferedCipherSuites(new[]
            {
                CipherSuite.TLS_AES_256_GCM_SHA384,
                CipherSuite.TLS_AES_128_GCM_SHA256,
                CipherSuite.TLS_CHACHA20_POLY1305_SHA256,
            });
            conn.EnableCertWithExternalPsk(psk);
            bool gotCert = false;
            conn.SetServerCertificateValidation(null, (cert, warnings) => { gotCert = cert != null && cert.Length > 0; return true; });
            if (useAsync) conn.HandshakeAsClientAsync("localhost", default).GetAwaiter().GetResult();
            else conn.HandshakeAsClient("localhost");
            stream.ReadTimeout = System.Threading.Timeout.Infinite;

            using var st = new TlsStream(conn, tcp);
            byte[] msg = Encoding.ASCII.GetBytes(new string('P', msgLen));
            st.Write(msg, 0, msg.Length);
            var buf = new byte[msgLen + 256];
            int got = 0;
            while (got < msgLen) { int n = st.Read(buf, got, buf.Length - got); if (n <= 0) break; got += n; }
            srv.Wait(8000);

            bool dataOk = got == msgLen && buf.AsSpan(0, msgLen).SequenceEqual(msg);
            Check($"{name}: encrypted data echo", dataOk);
            Check($"{name}: client negotiated cert+extern-PSK", conn.UsedCertWithExternalPsk);
            Check($"{name}: server negotiated cert+extern-PSK", serverMode);
            Check($"{name}: full cert handshake ran (not a resumption skip)", !conn.IsResumed && gotCert);
            if (serverErr != null) Check($"{name}: server error [{serverErr}]", false);
        }
        catch (Exception e) { Check($"{name} [{e.GetType().Name}: {e.Message}]", false); }
        finally { listener.Stop(); }
    }

    // Every experimental/optional negotiation knob must be configurable: a server allow-list that can
    // REFUSE a suite/group it actually supports, and a client signature_algorithms override that the
    // server honours. Each knob is checked both ways — the restriction blocks the handshake, and the
    // matching configuration completes it — so we know the option is wired, not inert.
    private static void ConfigurableNegotiation(TlsCertificate ca, TlsCertificate ecCert)
    {
        // Run one handshake with the given config; report success plus the negotiated group/suite.
        (bool ok, NamedGroup group, CipherSuite suite) Try(Action<TlsClient> configureClient, Action<TlsServer> configureServer)
        {
            int port = ++_port;
            var server = new TlsServer(ecCert) { HandshakeTimeoutMs = 8000 };
            configureServer(server);
            server.Listen(port);
            var srv = Task.Run(() =>
            {
                try
                {
                    using var s = server.Accept();
                    var b = new byte[64];
                    int n = s.Read(b, 0, b.Length);
                    if (n > 0) s.Write(b, 0, n);
                }
                catch { /* expected on the negative cases */ }
            });
            try
            {
                var c = new TlsClient { HandshakeTimeoutMs = 8000, CaCertificate = ca };
                configureClient(c);
                using var st = c.Connect("localhost", port);
                st.Write(new byte[] { 1, 2, 3, 4 }, 0, 4);
                var buf = new byte[64];
                bool ok = st.Read(buf, 0, buf.Length) == 4;
                return (ok, st.NegotiatedGroup, st.NegotiatedCipherSuite);
            }
            catch { return (false, default, default); }
            finally { srv.Wait(4000); server.Stop(); }
        }

        // 1) Server cipher-suite allow-list — refuses a suite it supports but the operator excluded.
        Check("server allow-list refuses a disallowed (AEGIS) suite",
            !Try(c => c.CipherSuites = new[] { CipherSuite.TLS_AEGIS_128L_SHA256 },
                 s => s.AllowedCipherSuites = new[] { CipherSuite.TLS_AES_256_GCM_SHA384, CipherSuite.TLS_AES_128_GCM_SHA256 }).ok);
        var aes = Try(c => c.CipherSuites = new[] { CipherSuite.TLS_AES_256_GCM_SHA384 },
                      s => s.AllowedCipherSuites = new[] { CipherSuite.TLS_AES_256_GCM_SHA384 });
        Check("server allow-list admits an allowed suite", aes.ok);
        Check("negotiated cipher suite is observable + correct", aes.suite == CipherSuite.TLS_AES_256_GCM_SHA384);

        // 2) Client supported_groups now follows NamedGroups, so a server allow-list that excludes the only
        //    group the client offers leaves no overlap → the handshake fails (no HRR fallback sneaks in).
        Check("server allow-list with no group in common fails the handshake",
            !Try(c => c.NamedGroups = new[] { NamedGroup.X25519MLKEM768 },
                 s => s.AllowedGroups = new[] { NamedGroup.X25519, NamedGroup.Secp256r1 }).ok);
        // Offer both; the server allow-list forces the classical group over the hybrid — and we can see it.
        var grp = Try(c => c.NamedGroups = new[] { NamedGroup.X25519MLKEM768, NamedGroup.X25519 },
                      s => s.AllowedGroups = new[] { NamedGroup.X25519 });
        Check("server allow-list admits an allowed group", grp.ok);
        Check("negotiated group is the allowed classical one, not the hybrid", grp.group == NamedGroup.X25519);

        // 3) Client signature_algorithms override reaches the server: advertising ONLY Ed25519 makes the
        //    server reject its own ECDSA-P256 leaf (its scheme wasn't offered); including it succeeds.
        Check("client sig-alg override (Ed25519-only) makes the server reject its ECDSA cert",
            !Try(c => c.SignatureSchemes = new[] { SignatureScheme.Ed25519 },
                 s => { }).ok);
        Check("client sig-alg override that includes the cert's scheme succeeds",
            Try(c => c.SignatureSchemes = new[] { SignatureScheme.EcdsaSecp256r1Sha256 },
                s => { }).ok);
    }

    // Establish a raw-TlsConnection loopback pair (the wrappers don't expose every knob), returning both
    // live connections so a test can drive post-handshake operations on each end. Handshake runs concurrently.
    private static (TlsConnection client, TlsConnection server, Action cleanup) RawPair(
        TlsCertificate ca, TlsCertificate serverCert, TlsCertificate? clientCert,
        Action<TlsConnection>? cfgClient = null, Action<TlsConnection>? cfgServer = null)
    {
        int port = ++_port;
        var listener = new TcpListener(System.Net.IPAddress.Loopback, port);
        listener.Start();
        TlsConnection? serverConn = null;
        TcpClient? serverTcp = null;
        Exception? serverErr = null;
        var srv = Task.Run(() =>
        {
            try
            {
                serverTcp = listener.AcceptTcpClient();
                var conn = new TlsConnection(serverTcp.GetStream(), isServer: true, serverCert, caCertificate: ca);
                cfgServer?.Invoke(conn);
                conn.HandshakeAsServer();
                serverConn = conn;
            }
            catch (Exception e) { serverErr = e; }
        });

        var clientTcp = new TcpClient { NoDelay = true };
        clientTcp.Connect("localhost", port);
        var clientConn = new TlsConnection(clientTcp.GetStream(), isServer: false, certificate: clientCert);
        clientConn.SetServerCertificateValidation(null, (_, _) => true);
        cfgClient?.Invoke(clientConn);
        clientConn.HandshakeAsClient("localhost");
        srv.Wait(8000);
        if (serverErr != null) throw serverErr;

        return (clientConn, serverConn!, () =>
        {
            try { clientTcp.Dispose(); } catch { }
            try { serverTcp?.Dispose(); } catch { }
            listener.Stop();
        });
    }

    // Exercises the opt-in features that previously had no dedicated end-to-end coverage.
    private static void OptInFeatures(TlsCertificate ca, TlsCertificate ecCert)
    {
        // --- ALPN (RFC 7301): overlap is "http/1.1"; both ends must agree. ---
        {
            var (c, s, cleanup) = RawPair(ca, ecCert, null,
                cfgClient: x => x.SetAlpnProtocols(new[] { "h2", "http/1.1" }),
                cfgServer: x => x.SetAlpnProtocols(new[] { "http/1.1" }));
            try
            {
                Check("ALPN: client + server agree on the protocol",
                    c.NegotiatedAlpn == "http/1.1" && s.NegotiatedAlpn == "http/1.1");
            }
            finally { cleanup(); }
        }

        // --- OCSP stapling (RFC 6066): server staples a response, client surfaces it verbatim. ---
        {
            byte[] ocsp = { 0x30, 0x05, 0x0A, 0x01, 0x00, 0x42 };
            var (c, s, cleanup) = RawPair(ca, ecCert, null,
                cfgClient: x => x.RequestOcspStapling(),
                cfgServer: x => x.SetOcspResponse(ocsp));
            try
            {
                Check("OCSP stapling: client receives the server's stapled response",
                    c.PeerOcspResponse != null && c.PeerOcspResponse.AsSpan().SequenceEqual(ocsp));
            }
            finally { cleanup(); }
        }

        // --- Exporter, channel binding, exported authenticator, KeyUpdate, post-handshake auth ---
        {
            var (c, s, cleanup) = RawPair(ca, ecCert, clientCert: ecCert,
                cfgClient: x => x.EnablePostHandshakeAuth());
            try
            {
                // Key exporter (RFC 5705 / RFC 8446 §7.5): both ends derive the same bytes.
                byte[] ctx = Encoding.ASCII.GetBytes("ctx-opentls13");
                byte[] ce = c.ExportKeyingMaterial("EXPERIMENTAL-opentls13", ctx, 32);
                byte[] se = s.ExportKeyingMaterial("EXPERIMENTAL-opentls13", ctx, 32);
                Check("exporter (RFC 5705/8446): client + server derive identical keying material",
                    ce.Length == 32 && ce.AsSpan().SequenceEqual(se));

                // Channel binding (RFC 9266) tls-exporter: identical on both ends.
                byte[] cb = c.GetChannelBinding(ChannelBindingType.TlsExporter);
                byte[] sb = s.GetChannelBinding(ChannelBindingType.TlsExporter);
                Check("channel binding (RFC 9266, tls-exporter): client + server agree",
                    cb.Length == 32 && cb.AsSpan().SequenceEqual(sb));

                // Exported authenticator (RFC 9261): server authenticates with its cert; client verifies.
                byte[] authCtx = Encoding.ASCII.GetBytes("rfc9261-context");
                byte[] auth = s.ExportAuthenticator(ecCert, authCtx, isServer: true);
                Check("exported authenticator (RFC 9261): a valid one verifies",
                    c.VerifyExportedAuthenticator(auth, authCtx, isServer: true, ca));
                auth[^1] ^= 0xFF;
                Check("exported authenticator (RFC 9261): a tampered one is rejected",
                    !c.VerifyExportedAuthenticator(auth, authCtx, isServer: true, ca));

                // KeyUpdate (RFC 8446 §4.6.3): client rotates its write key, then keeps sending under it.
                c.SendKeyUpdate(requestUpdate: false);
                byte[] ku = Encoding.ASCII.GetBytes("after-keyupdate");
                c.Write(ku, 0, ku.Length);
                var kb = new byte[64]; int kn = s.Read(kb, 0, kb.Length);
                Check("KeyUpdate: application data flows under the rotated keys",
                    kn == ku.Length && Encoding.ASCII.GetString(kb, 0, kn) == "after-keyupdate");

                // Post-handshake client auth (RFC 8446 §4.6.2): server requests, client presents its cert.
                // Sequenced single-threaded: each Write is flushed before the peer's Read drains it.
                s.RequestPostHandshakeAuth();
                byte[] pong = Encoding.ASCII.GetBytes("pong");
                s.Write(pong, 0, pong.Length);                 // unblocks the client Read once it answers the CR
                var pb = new byte[64]; c.Read(pb, 0, pb.Length); // processes CR (sends cert+CV+Fin), returns "pong"
                byte[] ping = Encoding.ASCII.GetBytes("ping");
                c.Write(ping, 0, ping.Length);
                var qb = new byte[64]; int qn = s.Read(qb, 0, qb.Length); // processes client cert, returns "ping"
                Check("post-handshake auth (RFC 8446 §4.6.2): server obtained the client certificate",
                    qn == ping.Length && Encoding.ASCII.GetString(qb, 0, qn) == "ping" && s.PeerCertificateData != null);
            }
            finally { cleanup(); }
        }

        // --- Record padding (RFC 8446 §5.4): a padded connection puts more bytes on the wire. ---
        RecordPadding(ecCert);
    }

    // Measures bytes the client writes for the same exchange with padding off vs on. Padding is applied
    // by the sender, so client-side counting suffices; the server strips it transparently on read.
    private static void RecordPadding(TlsCertificate ecCert)
    {
        long Run(int pad)
        {
            int port = ++_port;
            var listener = new TcpListener(System.Net.IPAddress.Loopback, port);
            listener.Start();
            var srv = Task.Run(() =>
            {
                try
                {
                    using var tcp = listener.AcceptTcpClient();
                    var conn = new TlsConnection(tcp.GetStream(), isServer: true, ecCert);
                    conn.HandshakeAsServer();
                    var b = new byte[64];
                    int n = conn.Read(b, 0, b.Length);
                    if (n > 0) conn.Write(b, 0, n);
                    Thread.Sleep(30);
                }
                catch { }
            });
            try
            {
                using var tcp = new TcpClient { NoDelay = true };
                tcp.Connect("localhost", port);
                var counter = new CountingStream(tcp.GetStream());
                var conn = new TlsConnection(counter, isServer: false);
                conn.SetServerCertificateValidation(null, (_, _) => true);
                conn.PaddingBlockSize = pad;
                conn.HandshakeAsClient("localhost");
                byte[] msg = Encoding.ASCII.GetBytes("0123456789");
                conn.Write(msg, 0, msg.Length);
                var buf = new byte[64];
                conn.Read(buf, 0, buf.Length);
                srv.Wait(6000);
                return counter.BytesWritten;
            }
            finally { listener.Stop(); }
        }

        long noPad = Run(0);
        long padded = Run(256);
        Check($"record padding: a padded connection writes more bytes ({padded} > {noPad})", padded > noPad);
    }

    // Counts bytes written to the wrapped stream (used to observe record padding).
    private sealed class CountingStream : Stream
    {
        private readonly Stream _inner;
        public long BytesWritten;
        public CountingStream(Stream inner) => _inner = inner;
        public override void Write(byte[] buffer, int offset, int count) { BytesWritten += count; _inner.Write(buffer, offset, count); }
        public override void Write(ReadOnlySpan<byte> buffer) { BytesWritten += buffer.Length; _inner.Write(buffer); }
        public override int Read(byte[] buffer, int offset, int count) => _inner.Read(buffer, offset, count);
        public override void Flush() => _inner.Flush();
        public override bool CanRead => true;
        public override bool CanWrite => true;
        public override bool CanSeek => false;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
    }

    // ML-KEM-768 (FIPS 203) primitive round-trip + implicit-rejection check. The hybrid TLS group
    // rides on this; a regression here would silently break X25519MLKEM768 key agreement.
    private static void MlKemRoundTrip()
    {
        var (ek, dk) = MlKem768.KeyGen();
        var (ssEncaps, ct) = MlKem768.Encaps(ek);
        byte[] ssDecaps = MlKem768.Decaps(dk, ct);
        Check("ML-KEM-768 sizes (ek=1184, dk=2400, ct=1088, ss=32)",
            ek.Length == 1184 && dk.Length == 2400 && ct.Length == 1088 && ssEncaps.Length == 32);
        Check("ML-KEM-768 Encaps/Decaps shared-secret agreement", Eqb(ssEncaps, ssDecaps));

        // FIPS 203 implicit rejection: a tampered ciphertext must decapsulate to a pseudo-random
        // secret (derived from the dk's rejection key z), NOT the original — and never throw.
        ct[0] ^= 0xFF;
        byte[] ssBad = MlKem768.Decaps(dk, ct);
        Check("ML-KEM-768 implicit rejection on corrupted ciphertext", !Eqb(ssBad, ssEncaps));
    }

    // Exercises true PSK resumption + 0-RTT early data + 0-RTT anti-replay end-to-end — paths that
    // had no runtime coverage before. The server now issues NewSessionTickets unsolicited (RFC 8446
    // §4.6.1) once the client advertises psk_dhe_ke, so resumption bootstraps with no special client
    // config beyond a TicketStore.
    private static void ResumptionAndEarlyData(string name, TlsCertificate cert)
    {
        int port = ++_port;
        var server = new TlsServer(cert)
        {
            TicketEncryption = new TicketEncryption(),
            Accept0Rtt = true,
            MaxEarlyDataSize = 16384,
        };
        server.Listen(port);

        var serverEarly = new byte[3][];
        string? serverErr = null;
        var srv = Task.Run(() =>
        {
            for (int i = 0; i < 3; i++)
            {
                try
                {
                    using var s = server.Accept();
                    serverEarly[i] = s.ReceivedEarlyData ?? Array.Empty<byte>();
                    var b = new byte[1024];
                    int n = s.Read(b);
                    if (n > 0) s.Write(b, 0, n);
                    Thread.Sleep(50);
                }
                catch (Exception e) { serverErr ??= $"conn{i}: {e.GetType().Name}: {e.Message}"; }
            }
        });

        try
        {
            // conn1 — full handshake. The post-handshake NewSessionTickets arrive before the echo on
            // the wire, so reading the echo also pumps them into the store via the ticket callback.
            var s1 = new SessionTicketStore();
            using (var st1 = new TlsClient { HandshakeTimeoutMs = 12000, TicketStore = s1 }.Connect("localhost", port))
            {
                var m = Encoding.ASCII.GetBytes("full");
                st1.Write(m);
                var buf = new byte[1024]; int got = st1.Read(buf);
                Check($"{name}: conn1 echo (full handshake)", got == m.Length && buf.AsSpan(0, got).SequenceEqual(m));
                Check($"{name}: conn1 NOT resumed", !st1.IsResumed);
            }

            var ticket = s1.Get("localhost");
            Check($"{name}: server issued a ticket unsolicited", ticket != null);
            if (ticket == null) return;

            // conn2 — resume with 0-RTT early data; the server must accept and surface it.
            byte[] early = Encoding.ASCII.GetBytes("zero-rtt-early-data");
            var s2 = new SessionTicketStore(); s2.Add("localhost", ticket);
            using (var st2 = new TlsClient { HandshakeTimeoutMs = 12000, TicketStore = s2 }.Connect("localhost", port, earlyData: early))
            {
                Check($"{name}: conn2 resumed (PSK)", st2.IsResumed);
                Check($"{name}: conn2 0-RTT accepted by client", st2.EarlyDataAccepted);
                var m = Encoding.ASCII.GetBytes("after");
                st2.Write(m);
                var buf = new byte[1024]; int got = st2.Read(buf);
                Check($"{name}: conn2 1-RTT echo", got == m.Length && buf.AsSpan(0, got).SequenceEqual(m));
            }
            Check($"{name}: server received the 0-RTT data",
                serverEarly[1].AsSpan().SequenceEqual(early));

            // conn3 — replay the SAME ticket with 0-RTT. Resumption still succeeds, but the early data
            // MUST be refused (single-use anti-replay, RFC 8446 §8).
            var s3 = new SessionTicketStore(); s3.Add("localhost", ticket);
            using (var st3 = new TlsClient { HandshakeTimeoutMs = 12000, TicketStore = s3 }.Connect("localhost", port, earlyData: early))
            {
                Check($"{name}: conn3 resumed (PSK)", st3.IsResumed);
                Check($"{name}: conn3 0-RTT replay REFUSED", !st3.EarlyDataAccepted);
                var m = Encoding.ASCII.GetBytes("again");
                st3.Write(m);
                var buf = new byte[1024]; int got = st3.Read(buf);
                Check($"{name}: conn3 1-RTT echo after replay refusal", got == m.Length && buf.AsSpan(0, got).SequenceEqual(m));
            }
            Check($"{name}: server did NOT surface replayed early data", serverEarly[2].Length == 0);
        }
        catch (Exception e) { Check($"{name} [{e.GetType().Name}: {e.Message}] | server: {serverErr}", false); }
        finally { srv.Wait(12000); server.Stop(); }
    }

    // Encrypted Client Hello (draft-esni-18): the client HPKE-seals a real-SNI ClientHelloInner under
    // the server's ECHConfig; the server decrypts and both drive the handshake off the inner CH, with
    // the §7.2 accept-confirmation binding it. A successful echo proves the inner transcript matched on
    // both sides (a wrong/outer transcript would fail Finished). Covers both HPKE AEADs + a reject.
    private static void EchHandshake(TlsCertificate cert)
    {
        Section("Loopback: Encrypted Client Hello (draft-ietf-tls-esni-18)");

        foreach (var (aead, name) in new[] {
            (Hpke.AEAD_AES_128_GCM, "AES-128-GCM"),
            (Hpke.AEAD_CHACHA20_POLY1305, "ChaCha20Poly1305") })
        {
            byte[] echPriv = X25519.GeneratePrivateKey();
            byte[] list = EncryptedClientHello.BuildEchConfigList(
                EncryptedClientHello.BuildEchConfig(7, X25519.PublicFromPrivate(echPriv),
                    new[] { (Hpke.KDF_HKDF_SHA256, aead) }, 64, "public.example.test"));

            int port = ++_port;
            var server = new TlsServer(cert) { EchPrivateKey = echPriv, EchConfigList = list };
            server.Listen(port);
            var srv = Task.Run(() =>
            {
                try { using var s = server.Accept(); var b = new byte[256]; int n = s.Read(b); if (n > 0) s.Write(b, 0, n); Thread.Sleep(50); }
                catch { }
            });
            try
            {
                var c = new TlsClient { HandshakeTimeoutMs = 12000, EchConfigList = list };
                using var st = c.Connect("localhost", port); // real SNI=localhost; observers see public.example.test
                Check($"ECH {name}: client confirms acceptance", st.EchAccepted);
                var msg = Encoding.ASCII.GetBytes("secret-over-ech");
                st.Write(msg);
                var buf = new byte[256]; int got = st.Read(buf);
                Check($"ECH {name}: echo over the inner handshake", got == msg.Length && buf.AsSpan(0, got).SequenceEqual(msg));
            }
            catch (Exception e) { Check($"ECH {name} [{e.GetType().Name}: {e.Message}]", false); }
            finally { srv.Wait(6000); server.Stop(); }
        }

        // Reject: client offers a config the server doesn't hold. The server can't decrypt, completes
        // to the public_name, and returns retry_configs; the client surfaces them (draft §7.1). The
        // public_name is "localhost" so the public-name handshake validates against the test cert.
        {
            byte[] clientPriv = X25519.GeneratePrivateKey();
            byte[] clientList = EncryptedClientHello.BuildEchConfigList(
                EncryptedClientHello.BuildEchConfig(1, X25519.PublicFromPrivate(clientPriv),
                    new[] { (Hpke.KDF_HKDF_SHA256, Hpke.AEAD_AES_128_GCM) }, 64, "localhost"));
            byte[] serverPriv = X25519.GeneratePrivateKey();
            byte[] serverList = EncryptedClientHello.BuildEchConfigList(
                EncryptedClientHello.BuildEchConfig(9, X25519.PublicFromPrivate(serverPriv),
                    new[] { (Hpke.KDF_HKDF_SHA256, Hpke.AEAD_AES_128_GCM) }, 64, "localhost"));
            int port = ++_port;
            var server = new TlsServer(cert) { EchPrivateKey = serverPriv, EchConfigList = serverList };
            server.Listen(port);
            var srv = Task.Run(() => { try { using var s = server.Accept(); var b = new byte[64]; int n = s.Read(b); if (n > 0) s.Write(b, 0, n); Thread.Sleep(50); } catch { } });
            try
            {
                var c = new TlsClient { HandshakeTimeoutMs = 12000, EchConfigList = clientList };
                using var st = c.Connect("localhost", port);
                var msg = Encoding.ASCII.GetBytes("public-name-handshake");
                st.Write(msg); var buf = new byte[64]; int got = st.Read(buf);
                Check("ECH reject: completes to public_name, not accepted", !st.EchAccepted && got == msg.Length);
                Check("ECH reject: client surfaced retry_configs", st.EchRetryConfigs != null && st.EchRetryConfigs.Length > 0);
            }
            catch (Exception e) { Check($"ECH reject [{e.GetType().Name}: {e.Message}]", false); }
            finally { srv.Wait(6000); server.Stop(); }
        }

        // Async ECH parity (ConnectAsync / AcceptAsync).
        {
            byte[] echPriv = X25519.GeneratePrivateKey();
            byte[] list = EncryptedClientHello.BuildEchConfigList(
                EncryptedClientHello.BuildEchConfig(7, X25519.PublicFromPrivate(echPriv),
                    new[] { (Hpke.KDF_HKDF_SHA256, Hpke.AEAD_AES_128_GCM) }, 64, "public.example.test"));
            int port = ++_port;
            var server = new TlsServer(cert) { EchPrivateKey = echPriv, EchConfigList = list };
            server.Listen(port);
            var srv = Task.Run(async () =>
            {
                try { using var s = await server.AcceptAsync(); var b = new byte[256]; int n = await s.ReadAsync(b, 0, b.Length); if (n > 0) await s.WriteAsync(b, 0, n); await Task.Delay(50); }
                catch { }
            });
            try
            {
                var c = new TlsClient { HandshakeTimeoutMs = 12000, EchConfigList = list };
                using var st = c.ConnectAsync("localhost", port).GetAwaiter().GetResult();
                Check("ECH async: client confirms acceptance", st.EchAccepted);
                var msg = Encoding.ASCII.GetBytes("async-secret-over-ech");
                st.WriteAsync(msg, 0, msg.Length).GetAwaiter().GetResult();
                var buf = new byte[256]; int got = st.ReadAsync(buf, 0, buf.Length).GetAwaiter().GetResult();
                Check("ECH async: echo over the inner handshake", got == msg.Length && buf.AsSpan(0, got).SequenceEqual(msg));
            }
            catch (Exception e) { Check($"ECH async [{e.GetType().Name}: {e.Message}]", false); }
            finally { srv.Wait(6000); server.Stop(); }
        }

        // GREASE-ECH: client emits a fake ECH ext; server (no ECH) ignores it and completes normally.
        {
            int port = ++_port;
            var server = new TlsServer(cert);
            server.Listen(port);
            var srv = Task.Run(() => { try { using var s = server.Accept(); var b = new byte[64]; int n = s.Read(b); if (n > 0) s.Write(b, 0, n); Thread.Sleep(50); } catch { } });
            try
            {
                var c = new TlsClient { HandshakeTimeoutMs = 12000, GreaseEch = true };
                using var st = c.Connect("localhost", port);
                var msg = Encoding.ASCII.GetBytes("greased");
                st.Write(msg);
                var buf = new byte[64]; int got = st.Read(buf);
                Check("GREASE-ECH: normal handshake completes, not accepted",
                    !st.EchAccepted && got == msg.Length && buf.AsSpan(0, got).SequenceEqual(msg));
            }
            catch (Exception e) { Check($"GREASE-ECH [{e.GetType().Name}: {e.Message}]", false); }
            finally { srv.Wait(6000); server.Stop(); }
        }
    }

    // Forced HelloRetryRequest (test knob) — exercises the HRR path end-to-end, which otherwise never
    // triggers in loopback (the server accepts any offered key-share group). Covers plain HRR and the
    // ECH HRR accept-confirmation (draft §7.2.1) on both sync and async.
    private static void ForceHrrHandshake(TlsCertificate cert)
    {
        Section("Loopback: HelloRetryRequest (forced) — plain + ECH");

        // Plain forced HRR: server sends one HRR, client retries on CH2, handshake completes.
        {
            int port = ++_port;
            var server = new TlsServer(cert) { ForceHelloRetryRequest = true };
            server.Listen(port);
            var srv = Task.Run(() => { try { using var s = server.Accept(); var b = new byte[256]; int n = s.Read(b); if (n > 0) s.Write(b, 0, n); Thread.Sleep(50); } catch { } });
            try
            {
                var c = new TlsClient { HandshakeTimeoutMs = 12000 };
                using var st = c.Connect("localhost", port);
                var msg = Encoding.ASCII.GetBytes("after-hrr");
                st.Write(msg); var buf = new byte[256]; int got = st.Read(buf);
                Check("HRR (forced): handshake completes after retry", got == msg.Length && buf.AsSpan(0, got).SequenceEqual(msg));
            }
            catch (Exception e) { Check($"HRR forced [{e.GetType().Name}: {e.Message}]", false); }
            finally { srv.Wait(6000); server.Stop(); }
        }

        // ECH + forced HRR (sync and async): the §7.2.1 HRR accept-confirmation flows; ECH still accepted on CH2.
        foreach (bool useAsync in new[] { false, true })
        {
            byte[] echPriv = X25519.GeneratePrivateKey();
            byte[] list = EncryptedClientHello.BuildEchConfigList(
                EncryptedClientHello.BuildEchConfig(7, X25519.PublicFromPrivate(echPriv),
                    new[] { (Hpke.KDF_HKDF_SHA256, Hpke.AEAD_AES_128_GCM) }, 64, "public.example.test"));
            string tag = useAsync ? "async" : "sync";
            int port = ++_port;
            var server = new TlsServer(cert) { EchPrivateKey = echPriv, EchConfigList = list, ForceHelloRetryRequest = true };
            server.Listen(port);
            var srv = Task.Run(async () =>
            {
                try
                {
                    using var s = useAsync ? await server.AcceptAsync() : server.Accept();
                    var b = new byte[256]; int n = s.Read(b); if (n > 0) s.Write(b, 0, n); Thread.Sleep(50);
                }
                catch { }
            });
            try
            {
                var c = new TlsClient { HandshakeTimeoutMs = 12000, EchConfigList = list };
                using var st = useAsync ? c.ConnectAsync("localhost", port).GetAwaiter().GetResult() : c.Connect("localhost", port);
                Check($"ECH+HRR {tag}: client confirms acceptance after retry", st.EchAccepted);
                var msg = Encoding.ASCII.GetBytes("ech-over-hrr-" + tag);
                st.Write(msg); var buf = new byte[256]; int got = st.Read(buf);
                Check($"ECH+HRR {tag}: echo over the inner handshake", got == msg.Length && buf.AsSpan(0, got).SequenceEqual(msg));
            }
            catch (Exception e) { Check($"ECH+HRR {tag} [{e.GetType().Name}: {e.Message}]", false); }
            finally { srv.Wait(6000); server.Stop(); }
        }
    }

    // Exercises the async handshake state machines (HandshakeAsClientAsync / HandshakeAsServerAsync)
    // + async record IO — the loopback Handshake() helper only drives the sync paths.
    private static void AsyncHandshake(string name, TlsCertificate cert, NamedGroup[]? groups, int msgLen)
    {
        int port = ++_port;
        var server = new TlsServer(cert);
        server.Listen(port);
        var srv = Task.Run(async () =>
        {
            try
            {
                using var s = await server.AcceptAsync();
                var b = new byte[msgLen + 4096];
                int got = 0;
                while (got < msgLen) { int n = await s.ReadAsync(b, got, b.Length - got); if (n <= 0) break; got += n; }
                await s.WriteAsync(b, 0, got);
                await Task.Delay(100);
            }
            catch { }
        });
        try
        {
            var c = new TlsClient { HandshakeTimeoutMs = 12000 };
            if (groups != null) c.NamedGroups = groups;
            using var st = c.ConnectAsync("localhost", port).GetAwaiter().GetResult();
            byte[] msg = Encoding.ASCII.GetBytes(new string('A', msgLen));
            st.WriteAsync(msg, 0, msg.Length).GetAwaiter().GetResult();
            var buf = new byte[msgLen + 4096];
            int got = 0;
            while (got < msgLen) { int n = st.ReadAsync(buf, got, buf.Length - got).GetAwaiter().GetResult(); if (n <= 0) break; got += n; }
            Check(name, got == msgLen && buf.AsSpan(0, got).SequenceEqual(msg));
        }
        catch (Exception e) { Check($"{name} [{e.GetType().Name}: {e.Message}]", false); }
        finally { srv.Wait(6000); server.Stop(); }
    }

    private static void MutualTls(TlsCertificate ca, TlsCertificate serverCert, bool useCompression = false)
    {
        int port = ++_port;
        var clientCert = CertificateUtils.IssueCertificate("test-client", ca, CertificateProfile.Client);
        var server = new TlsServer(serverCert)
        {
            RequireClientCertificate = true,
            CaCertificate = ca,
            UseCertificateCompression = useCompression, // RFC 8879: also advertises it in CertificateRequest
        };
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
            Check($"mTLS handshake + client cert seen{(useCompression ? " (compressed client cert, RFC 8879)" : "")}",
                buf.AsSpan(0, n).SequenceEqual(msg) && seenCn == "test-client");
        }
        catch (Exception e) { Check($"mTLS [{e.GetType().Name}: {e.Message}]", false); }
        finally { srv.Wait(6000); server.Stop(); }
    }
}
