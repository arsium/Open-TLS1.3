using System.Text;
using TLS;

string host = "localhost";
int port = 8444;

if (args.Length >= 1) host = args[0];
if (args.Length >= 2) port = int.Parse(args[1]);

// Load client certificate for mTLS (if available)
TlsCertificate? clientCert = null;
if (File.Exists("client.pfx"))
{
    clientCert = CertificateUtils.ImportPfx(File.ReadAllBytes("client.pfx"), "password");
    Console.WriteLine("[*] Loaded client certificate for mTLS");
}

Console.WriteLine($"[*] Connecting to {host}:{port} (async)...");

var client = new TlsClient();
using var stream = clientCert != null
    ? await client.ConnectAsync(host, port, clientCert)
    : await client.ConnectAsync(host, port);
Console.WriteLine("[+] TLS 1.3 handshake complete (async)");

string message = "Hello from TLS 1.3 async client!";
await stream.WriteAsync(Encoding.UTF8.GetBytes(message));
Console.WriteLine($"[>] {message}");

byte[] response = await stream.ReadAllAsync();
Console.WriteLine($"[<] {Encoding.UTF8.GetString(response)}");
