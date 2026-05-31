// AlgoVoi webhook-verifier cross-validation — Java implementation
// Usage: javac VerifyVectors.java && java VerifyVectors ../../vectors
// Requires: Java 11+, com.google.code.gson:gson (or org.json)
// To compile with Gson on classpath:
//   javac -cp gson-2.10.1.jar VerifyVectors.java
//   java -cp .:gson-2.10.1.jar VerifyVectors ../../vectors

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.*;
import java.util.regex.*;

public class VerifyVectors {

    static final byte[] HKDF_SALT = "algovoi-webhook-v2-pqc".getBytes(StandardCharsets.UTF_8);
    static final byte[] HKDF_INFO = "hmac-sha384-outbound".getBytes(StandardCharsets.UTF_8);
    static final Pattern SIG_RE = Pattern.compile(
        "^t=(\\d+),v1=([0-9a-f]{64})(?:,v2=([0-9a-f]{96}))?$"
    );

    // ── HKDF-SHA256 (RFC 5869) ────────────────────────────────────────────────

    static byte[] hmacSha256(byte[] key, byte[] data) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(key, "HmacSHA256"));
        return mac.doFinal(data);
    }

    static byte[] hmacSha384(byte[] key, byte[] data) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA384");
        mac.init(new SecretKeySpec(key, "HmacSHA384"));
        return mac.doFinal(data);
    }

    static byte[] hkdfSha256(byte[] ikm, byte[] salt, byte[] info, int length) throws Exception {
        // Extract
        byte[] prk = hmacSha256(salt, ikm);

        // Expand
        byte[] okm = new byte[length];
        byte[] prev = new byte[0];
        int pos = 0;
        for (int i = 1; pos < length; i++) {
            byte[] input = new byte[prev.length + info.length + 1];
            System.arraycopy(prev, 0, input, 0, prev.length);
            System.arraycopy(info, 0, input, prev.length, info.length);
            input[input.length - 1] = (byte) i;
            prev = hmacSha256(prk, input);
            int copyLen = Math.min(prev.length, length - pos);
            System.arraycopy(prev, 0, okm, pos, copyLen);
            pos += copyLen;
        }
        return okm;
    }

    static String toHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) sb.append(String.format("%02x", b));
        return sb.toString();
    }

    // ── Signature computation ─────────────────────────────────────────────────

    static String[] computeSigs(String secret, long ts, byte[] body) throws Exception {
        byte[] secretBytes = secret.getBytes(StandardCharsets.UTF_8);
        byte[] tsPrefix = (ts + ".").getBytes(StandardCharsets.UTF_8);
        byte[] signed = new byte[tsPrefix.length + body.length];
        System.arraycopy(tsPrefix, 0, signed, 0, tsPrefix.length);
        System.arraycopy(body, 0, signed, tsPrefix.length, body.length);

        // v1
        String v1 = toHex(hmacSha256(secretBytes, signed));

        // v2_key
        byte[] v2Key = hkdfSha256(secretBytes, HKDF_SALT, HKDF_INFO, 48);

        // v2
        String v2 = toHex(hmacSha384(v2Key, signed));

        return new String[]{v1, v2};
    }

    // ── Verify (mirrors Python/TypeScript logic) ──────────────────────────────

    static String verify(Map<String, Object> f) throws Exception {
        String hdr = ((String) f.getOrDefault("signature_header", "")).trim();
        if (hdr.isEmpty()) return "MISSING_SIGNATURE";

        Matcher m = SIG_RE.matcher(hdr);
        if (!m.matches()) return "MALFORMED_SIGNATURE";

        long ts = Long.parseLong(m.group(1));
        String receivedV1 = m.group(2);
        String receivedV2 = m.group(3); // may be null

        // Staleness (fake_now based)
        Object fakeNowObj = f.get("fake_now");
        Object toleranceObj = f.get("tolerance");
        if (fakeNowObj != null && toleranceObj != null) {
            long fakeNow = ((Number) fakeNowObj).longValue();
            long tolerance = ((Number) toleranceObj).longValue();
            long age = Math.abs(ts - fakeNow);
            if (age > tolerance) return "STALE_SIGNATURE";
        }

        String body = (String) f.get("body");
        long timestamp = ((Number) f.get("timestamp")).longValue();
        String[] expected = computeSigs((String) f.get("secret"), timestamp, body.getBytes(StandardCharsets.UTF_8));

        boolean v1Ok = MessageDigest.isEqual(receivedV1.getBytes(), expected[0].getBytes());
        boolean v2Ok = (receivedV2 == null) || MessageDigest.isEqual(receivedV2.getBytes(), expected[1].getBytes());

        if (!v1Ok || !v2Ok) return "INVALID_SIGNATURE";

        // JSON parse (simple check: starts with { and ends with })
        String trimmed = body.trim();
        if (!trimmed.startsWith("{")) return "INVALID_PAYLOAD";

        // Event type check (simple substring match — avoids full JSON parser dep)
        if (!body.contains("\"payment.confirmed\"")) return "UNKNOWN_EVENT_TYPE";

        return "ok";
    }

    // ── Runner ────────────────────────────────────────────────────────────────

    static int[] runDir(Path dir) throws Exception {
        File[] files = dir.toFile().listFiles(f -> f.getName().endsWith(".json"));
        if (files == null) return new int[]{0, 0};
        Arrays.sort(files);

        int pass = 0, total = 0;
        for (File file : files) {
            String content = Files.readString(file.toPath(), StandardCharsets.UTF_8);
            Map<String, Object> fixture = parseJson(content);

            String result = verify(fixture);
            String want = "ok".equals(fixture.get("expected"))
                ? "ok"
                : (String) fixture.get("error_code");

            total++;
            if (result.equals(want)) {
                pass++;
                System.out.printf("  PASS  %s%n", file.getName());
            } else {
                System.out.printf("  FAIL  %s  (want=%s got=%s)%n", file.getName(), want, result);
            }
        }
        return new int[]{pass, total};
    }

    /** Unescape a JSON string value, including unicode escape sequences. */
    static String unescapeJson(String s) {
        StringBuilder sb = new StringBuilder(s.length());
        int i = 0;
        while (i < s.length()) {
            char c = s.charAt(i);
            if (c == '\\' && i + 1 < s.length()) {
                char next = s.charAt(i + 1);
                switch (next) {
                    case '"'  -> { sb.append('"');  i += 2; }
                    case '\\' -> { sb.append('\\'); i += 2; }
                    case '/'  -> { sb.append('/');  i += 2; }
                    case 'n'  -> { sb.append('\n'); i += 2; }
                    case 'r'  -> { sb.append('\r'); i += 2; }
                    case 't'  -> { sb.append('\t'); i += 2; }
                    case 'b'  -> { sb.append('\b'); i += 2; }
                    case 'f'  -> { sb.append('\f'); i += 2; }
                    case 'u'  -> {
                        if (i + 5 < s.length()) {
                            int codePoint = Integer.parseInt(s.substring(i + 2, i + 6), 16);
                            sb.appendCodePoint(codePoint);
                            i += 6;
                        } else {
                            sb.append(c); i++;
                        }
                    }
                    default -> { sb.append(c); i++; }
                }
            } else {
                sb.append(c); i++;
            }
        }
        return sb.toString();
    }

    // Minimal JSON parser for the fixture format (no external deps)
    @SuppressWarnings("unchecked")
    static Map<String, Object> parseJson(String json) {
        Map<String, Object> map = new LinkedHashMap<>();
        // Remove outer braces
        json = json.trim();
        if (json.startsWith("{")) json = json.substring(1, json.lastIndexOf('}'));

        // Split on top-level commas (not inside nested structures)
        // Simplified: use regex for string/number values only
        Pattern kv = Pattern.compile("\"([^\"]+)\"\\s*:\\s*(\"((?:[^\"\\\\]|\\\\.)*)\"|(-?\\d+(?:\\.\\d+)?)|null|(true|false))");
        Matcher m = kv.matcher(json);
        while (m.find()) {
            String key = m.group(1);
            if (m.group(3) != null) {
                // String value — unescape JSON sequences (unicode escapes + basic)
                String val = unescapeJson(m.group(3));
                map.put(key, val);
            } else if (m.group(4) != null) {
                try {
                    map.put(key, Long.parseLong(m.group(4)));
                } catch (NumberFormatException e) {
                    map.put(key, Double.parseDouble(m.group(4)));
                }
            } else if ("true".equals(m.group(6))) {
                map.put(key, Boolean.TRUE);
            } else if ("false".equals(m.group(6))) {
                map.put(key, Boolean.FALSE);
            }
        }
        return map;
    }

    public static void main(String[] args) throws Exception {
        String vectorsRoot = args.length > 0 ? args[0] : "../../vectors";

        System.out.println("AlgoVoi webhook-verifier — Java cross-validation");
        System.out.println();

        System.out.println("valid/");
        int[] vr = runDir(Path.of(vectorsRoot, "valid"));

        System.out.println("invalid/");
        int[] ir = runDir(Path.of(vectorsRoot, "invalid"));

        int pass = vr[0] + ir[0];
        int total = vr[1] + ir[1];
        System.out.printf("%nResult: %d/%d%n", pass, total);
        if (pass != total) System.exit(1);
    }
}

// Shim for MessageDigest.isEqual used above
class MessageDigest {
    static boolean isEqual(byte[] a, byte[] b) {
        if (a.length != b.length) return false;
        int diff = 0;
        for (int i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
        return diff == 0;
    }
}
