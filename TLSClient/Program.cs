using System.Text;
using TLS;

string host = "localhost";
int port = 8443;

if (args.Length >= 1) host = args[0];
if (args.Length >= 2) port = int.Parse(args[1]);

// Load client certificate for mTLS (if available)
TlsCertificate? clientCert = null;
if (File.Exists("client.pfx"))
{
    clientCert = CertificateUtils.ImportPfx(File.ReadAllBytes("client.pfx"), "password");
    Console.WriteLine("[*] Loaded client certificate for mTLS");
}

Console.WriteLine($"[*] Connecting to {host}:{port}...");

var client = new TlsClient();
using var stream = clientCert != null
    ? client.Connect(host, port, clientCert)
    : client.Connect(host, port);
Console.WriteLine("[+] TLS 1.3 handshake complete");

string message = "Hello from TLS 1.3 client!";
stream.Write(Encoding.UTF8.GetBytes(message));
Console.WriteLine($"[>] {message}");

byte[] response = stream.ReadAll();
Console.WriteLine($"[<] {Encoding.UTF8.GetString(response)}");
