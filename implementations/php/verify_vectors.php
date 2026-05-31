<?php
/**
 * AlgoVoi webhook-verifier cross-validation — PHP implementation
 * Usage: php verify_vectors.php ../../vectors
 * Requires: PHP 7.4+ with ext-json, ext-hash
 */

const HKDF_SALT = "algovoi-webhook-v2-pqc";
const HKDF_INFO = "hmac-sha384-outbound";
const SIG_RE    = '/^t=(\d+),v1=([0-9a-f]{64})(?:,v2=([0-9a-f]{96}))?$/';

// ── HKDF-SHA256 (RFC 5869) ────────────────────────────────────────────────────

function hkdf_sha256(string $ikm, string $salt, string $info, int $length): string {
    // Extract
    $prk = hash_hmac('sha256', $ikm, $salt, true);

    // Expand
    $okm  = '';
    $prev = '';
    $i    = 1;
    while (strlen($okm) < $length) {
        $prev = hash_hmac('sha256', $prev . $info . chr($i++), $prk, true);
        $okm .= $prev;
    }
    return substr($okm, 0, $length);
}

// ── Signature computation ─────────────────────────────────────────────────────

function compute_sigs(string $secret, int $ts, string $body): array {
    $signed = $ts . '.' . $body;

    // v1: HMAC-SHA256
    $v1 = hash_hmac('sha256', $signed, $secret);

    // v2_key: HKDF-SHA256(secret, salt, info, 48)
    $v2_key = hkdf_sha256($secret, HKDF_SALT, HKDF_INFO, 48);

    // v2: HMAC-SHA384
    $v2 = hash_hmac('sha384', $signed, $v2_key);

    return [$v1, $v2];
}

// ── Verify ────────────────────────────────────────────────────────────────────

function verify(array $f): string {
    $hdr = trim($f['signature_header'] ?? '');
    if ($hdr === '') return 'MISSING_SIGNATURE';

    if (!preg_match(SIG_RE, $hdr, $m)) return 'MALFORMED_SIGNATURE';

    $ts           = (int) $m[1];
    $received_v1  = $m[2];
    $received_v2  = $m[3] ?? null;

    // Staleness (fake_now based)
    if (isset($f['fake_now'], $f['tolerance'])) {
        $age = abs($ts - (int) $f['fake_now']);
        if ($age > (int) $f['tolerance']) return 'STALE_SIGNATURE';
    }

    [$expected_v1, $expected_v2] = compute_sigs(
        $f['secret'],
        (int) $f['timestamp'],
        $f['body']
    );

    $v1_ok = hash_equals($received_v1, $expected_v1);
    $v2_ok = ($received_v2 === null) || hash_equals($received_v2, $expected_v2);

    if (!$v1_ok || !$v2_ok) return 'INVALID_SIGNATURE';

    // JSON parse
    $event = json_decode($f['body'], true);
    if (json_last_error() !== JSON_ERROR_NONE || !is_array($event)) {
        return 'INVALID_PAYLOAD';
    }

    // Event type
    if (($event['type'] ?? '') !== 'payment.confirmed') return 'UNKNOWN_EVENT_TYPE';

    return 'ok';
}

// ── Runner ────────────────────────────────────────────────────────────────────

function run_dir(string $dir): array {
    $files = glob($dir . '/*.json');
    if (!$files) return [0, 0];
    sort($files);

    $pass = $total = 0;
    foreach ($files as $path) {
        $fixture = json_decode(file_get_contents($path), true);
        $result  = verify($fixture);
        $want    = $fixture['expected'] === 'ok' ? 'ok' : ($fixture['error_code'] ?? '');

        $total++;
        if ($result === $want) {
            $pass++;
            echo "  PASS  " . basename($path) . "\n";
        } else {
            echo "  FAIL  " . basename($path) . "  (want=$want got=$result)\n";
        }
    }
    return [$pass, $total];
}

// ── Main ──────────────────────────────────────────────────────────────────────

$vectors_root = $argv[1] ?? '../../vectors';

echo "AlgoVoi webhook-verifier — PHP cross-validation\n\n";

echo "valid/\n";
[$vp, $vt] = run_dir("$vectors_root/valid");

echo "invalid/\n";
[$ip, $it] = run_dir("$vectors_root/invalid");

$pass  = $vp + $ip;
$total = $vt + $it;
echo "\nResult: $pass/$total\n";
exit($pass === $total ? 0 : 1);
