// AlgoVoi webhook-verifier cross-validation — .NET / C# implementation
// Usage: dotnet run -- ../../vectors
// Requires: .NET 5+ (HKDF is built-in from .NET 5)

using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

static class VerifyVectors
{
    static readonly byte[] HkdfSalt = Encoding.UTF8.GetBytes("algovoi-webhook-v2-pqc");
    static readonly byte[] HkdfInfo = Encoding.UTF8.GetBytes("hmac-sha384-outbound");

    static readonly Regex SigRe = new Regex(
        @"^t=(\d+),v1=([0-9a-f]{64})(?:,v2=([0-9a-f]{96}))?$",
        RegexOptions.Compiled
    );

    // ── HKDF-SHA256 ──────────────────────────────────────────────────────────

    static byte[] HkdfSha256(byte[] ikm, byte[] salt, byte[] info, int length)
    {
        // .NET 5+ built-in HKDF
        return HKDF.DeriveKey(HashAlgorithmName.SHA256, ikm, length, salt, info);
    }

    // ── Signature computation ─────────────────────────────────────────────────

    static (string v1, string v2) ComputeSigs(string secret, long ts, byte[] body)
    {
        byte[] secretBytes = Encoding.UTF8.GetBytes(secret);
        byte[] tsPrefix = Encoding.UTF8.GetBytes($"{ts}.");
        byte[] signed = new byte[tsPrefix.Length + body.Length];
        Buffer.BlockCopy(tsPrefix, 0, signed, 0, tsPrefix.Length);
        Buffer.BlockCopy(body, 0, signed, tsPrefix.Length, body.Length);

        // v1: HMAC-SHA256
        using var hmac1 = new HMACSHA256(secretBytes);
        string v1 = Convert.ToHexString(hmac1.ComputeHash(signed)).ToLowerInvariant();

        // v2_key: HKDF
        byte[] v2Key = HkdfSha256(secretBytes, HkdfSalt, HkdfInfo, 48);

        // v2: HMAC-SHA384
        using var hmac2 = new HMACSHA384(v2Key);
        string v2 = Convert.ToHexString(hmac2.ComputeHash(signed)).ToLowerInvariant();

        return (v1, v2);
    }

    // ── Verify ────────────────────────────────────────────────────────────────

    static string Verify(JsonElement f)
    {
        string hdr = f.TryGetProperty("signature_header", out var sh)
            ? sh.GetString()!.Trim()
            : "";

        if (string.IsNullOrEmpty(hdr)) return "MISSING_SIGNATURE";

        var m = SigRe.Match(hdr);
        if (!m.Success) return "MALFORMED_SIGNATURE";

        long ts = long.Parse(m.Groups[1].Value);
        string receivedV1 = m.Groups[2].Value;
        string? receivedV2 = m.Groups[3].Success ? m.Groups[3].Value : null;

        // Staleness (fake_now based)
        if (f.TryGetProperty("fake_now", out var fn) && f.TryGetProperty("tolerance", out var tol))
        {
            long age = Math.Abs(ts - fn.GetInt64());
            if (age > tol.GetInt64()) return "STALE_SIGNATURE";
        }

        string secret = f.GetProperty("secret").GetString()!;
        long timestamp = f.GetProperty("timestamp").GetInt64();
        byte[] body = Encoding.UTF8.GetBytes(f.GetProperty("body").GetString()!);

        var (expectedV1, expectedV2) = ComputeSigs(secret, timestamp, body);

        bool v1Ok = CryptographicOperations.FixedTimeEquals(
            Encoding.UTF8.GetBytes(receivedV1),
            Encoding.UTF8.GetBytes(expectedV1)
        );
        bool v2Ok = receivedV2 == null ||
            CryptographicOperations.FixedTimeEquals(
                Encoding.UTF8.GetBytes(receivedV2),
                Encoding.UTF8.GetBytes(expectedV2)
            );

        if (!v1Ok || !v2Ok) return "INVALID_SIGNATURE";

        // JSON parse
        string bodyStr = f.GetProperty("body").GetString()!;
        JsonElement parsed;
        try
        {
            parsed = JsonSerializer.Deserialize<JsonElement>(bodyStr);
        }
        catch
        {
            return "INVALID_PAYLOAD";
        }

        if (parsed.ValueKind != JsonValueKind.Object) return "INVALID_PAYLOAD";

        string eventType = parsed.TryGetProperty("type", out var t) ? t.GetString() ?? "" : "";
        if (eventType != "payment.confirmed") return "UNKNOWN_EVENT_TYPE";

        return "ok";
    }

    // ── Runner ────────────────────────────────────────────────────────────────

    static (int pass, int total) RunDir(string dir)
    {
        var files = Directory.GetFiles(dir, "*.json");
        Array.Sort(files);

        int pass = 0, total = 0;
        foreach (var path in files)
        {
            using var doc = JsonDocument.Parse(File.ReadAllText(path));
            var f = doc.RootElement;

            string result = Verify(f);
            string want = f.GetProperty("expected").GetString() == "ok"
                ? "ok"
                : (f.TryGetProperty("error_code", out var ec) ? ec.GetString()! : "");

            total++;
            if (result == want)
            {
                pass++;
                Console.WriteLine($"  PASS  {Path.GetFileName(path)}");
            }
            else
            {
                Console.WriteLine($"  FAIL  {Path.GetFileName(path)}  (want={want} got={result})");
            }
        }
        return (pass, total);
    }

    static int Main(string[] args)
    {
        string vectorsRoot = args.Length > 0 ? args[0] : "../../vectors";

        Console.WriteLine("AlgoVoi webhook-verifier — .NET cross-validation");
        Console.WriteLine();

        Console.WriteLine("valid/");
        var (vp, vt) = RunDir(Path.Combine(vectorsRoot, "valid"));

        Console.WriteLine("invalid/");
        var (ip, it) = RunDir(Path.Combine(vectorsRoot, "invalid"));

        int pass = vp + ip, total = vt + it;
        Console.WriteLine($"\nResult: {pass}/{total}");
        return pass == total ? 0 : 1;
    }
}
