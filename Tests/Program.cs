using Tests;

if (args.Contains("mintest"))
{
    MinTLS.MinBcTest.Run();
    return 0;
}

if (args.Contains("bench"))
{
    Benchmark.Run();
    return 0;
}

if (args.Contains("profile"))
{
    Profile.Run();
    return 0;
}

if (args.Contains("bulk"))
{
    return BulkTests.Run();
}

if (args.Contains("fuzz"))
{
    int iters = 10000;
    int idx = Array.IndexOf(args, "fuzz");
    if (idx + 1 < args.Length && int.TryParse(args[idx + 1], out int n)) iters = n;
    return Fuzz.Run(iters);
}

Console.WriteLine("Open-TLS 1.3 — test vector & loopback suite");

CryptoVectorTests.Run();
LoopbackTests.Run();

return T.Summary();
