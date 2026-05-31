#!/usr/bin/env ruby
# AlgoVoi webhook-verifier cross-validation — Ruby implementation
# Usage: ruby verify_vectors.rb ../../vectors
# Requires: Ruby 2.7+ (openssl standard library)

require 'json'
require 'openssl'

HKDF_SALT = "algovoi-webhook-v2-pqc"
HKDF_INFO = "hmac-sha384-outbound"
SIG_RE    = /\At=(\d+),v1=([0-9a-f]{64})(?:,v2=([0-9a-f]{96}))?\z/

# ── HKDF-SHA256 (RFC 5869) ─────────────────────────────────────────────────────

def hkdf_sha256(ikm, salt, info, length)
  # Extract
  prk = OpenSSL::HMAC.digest('SHA256', salt, ikm)

  # Expand
  okm  = ""
  prev = ""
  i    = 1
  while okm.bytesize < length
    prev = OpenSSL::HMAC.digest('SHA256', prk, prev + info + i.chr)
    okm += prev
    i += 1
  end
  okm.byteslice(0, length)
end

# ── Signature computation ──────────────────────────────────────────────────────

def compute_sigs(secret, ts, body)
  signed = "#{ts}.#{body}"

  # v1: HMAC-SHA256
  v1 = OpenSSL::HMAC.hexdigest('SHA256', secret, signed)

  # v2_key: HKDF-SHA256
  v2_key = hkdf_sha256(secret, HKDF_SALT, HKDF_INFO, 48)

  # v2: HMAC-SHA384
  v2 = OpenSSL::HMAC.hexdigest('SHA384', v2_key, signed)

  [v1, v2]
end

# ── Verify ─────────────────────────────────────────────────────────────────────

def verify(f)
  hdr = (f['signature_header'] || '').strip
  return 'MISSING_SIGNATURE' if hdr.empty?

  m = SIG_RE.match(hdr)
  return 'MALFORMED_SIGNATURE' unless m

  ts          = m[1].to_i
  received_v1 = m[2]
  received_v2 = m[3]

  # Staleness (fake_now based)
  if f['fake_now'] && f['tolerance']
    age = (ts - f['fake_now']).abs
    return 'STALE_SIGNATURE' if age > f['tolerance']
  end

  expected_v1, expected_v2 = compute_sigs(f['secret'], f['timestamp'], f['body'])

  v1_ok = OpenSSL.secure_compare(received_v1, expected_v1)
  v2_ok = received_v2.nil? || OpenSSL.secure_compare(received_v2, expected_v2)

  return 'INVALID_SIGNATURE' unless v1_ok && v2_ok

  # JSON parse
  begin
    event = JSON.parse(f['body'])
  rescue JSON::ParserError
    return 'INVALID_PAYLOAD'
  end
  return 'INVALID_PAYLOAD' unless event.is_a?(Hash)

  # Event type
  return 'UNKNOWN_EVENT_TYPE' if event['type'] != 'payment.confirmed'

  'ok'
end

# ── Runner ─────────────────────────────────────────────────────────────────────

def run_dir(dir)
  files = Dir.glob(File.join(dir, '*.json')).sort
  pass = total = 0

  files.each do |path|
    fixture = JSON.parse(File.read(path, encoding: 'utf-8'))
    result  = verify(fixture)
    want    = fixture['expected'] == 'ok' ? 'ok' : fixture['error_code']

    total += 1
    if result == want
      pass += 1
      puts "  PASS  #{File.basename(path)}"
    else
      puts "  FAIL  #{File.basename(path)}  (want=#{want} got=#{result})"
    end
  end
  [pass, total]
end

# ── Main ───────────────────────────────────────────────────────────────────────

vectors_root = ARGV[0] || '../../vectors'

puts "AlgoVoi webhook-verifier — Ruby cross-validation"
puts

puts "valid/"
vp, vt = run_dir(File.join(vectors_root, 'valid'))

puts "invalid/"
ip, it = run_dir(File.join(vectors_root, 'invalid'))

pass  = vp + ip
total = vt + it
puts "\nResult: #{pass}/#{total}"
exit(pass == total ? 0 : 1)
