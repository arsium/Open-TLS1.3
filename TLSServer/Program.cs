using System.Text;
using TLS;

// Generate CA + server cert (CA-signed)
var ca = CertificateUtils.GenerateCA("TLS Demo CA");
var serverCert = CertificateUtils.IssueCertificate("localhost", ca, CertificateProfile.Server);
Console.WriteLine("[*] Generated CA + server certificate");

// Issue a client certificate and export as PFX for the client
var clientCert = CertificateUtils.IssueCertificate("demo-client", ca, CertificateProfile.Client);
byte[] clientPfx = CertificateUtils.ExportPfx(clientCert, "password", ca);
File.WriteAllBytes("client.pfx", clientPfx);
Console.WriteLine("[*] Exported client.pfx for mTLS");

// Verify chain works
Console.WriteLine($"[*] Server cert signed by CA: {CertificateUtils.VerifyChain(serverCert, ca)}");
Console.WriteLine($"[*] Client cert signed by CA: {CertificateUtils.VerifyChain(clientCert, ca)}");

var server = new TlsServer(serverCert);
server.RequireClientCertificate = true;
server.CaCertificate = ca;
server.Listen(8443);
Console.WriteLine("[*] TLS 1.3 mTLS server listening on port 8443...");

while (true)
{
    try
    {
        using var stream = server.Accept();
        Console.WriteLine("[+] Client connected — mTLS handshake complete");

        if (stream.PeerCertificate != null)
        {
            string cn = CertificateUtils.ExtractCommonName(stream.PeerCertificate);
            Console.WriteLine($"[+] Client certificate: {cn}");
        }

        byte[] data = stream.ReadAll();
        string received = Encoding.UTF8.GetString(data);
        Console.WriteLine($"[<] {received}");

        string response = $"Echo: {received}";
        stream.Write(Encoding.UTF8.GetBytes(response));
        Console.WriteLine($"[>] {response}");
    }
    catch (TlsException ex)
    {
        Console.WriteLine($"[!] TLS error: {ex.Alert} — {ex.Message}");
    }
    catch (Exception ex)
    {
        Console.WriteLine($"[!] Error: {ex.Message}");
    }
}
