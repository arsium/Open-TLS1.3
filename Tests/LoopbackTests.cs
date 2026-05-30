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
