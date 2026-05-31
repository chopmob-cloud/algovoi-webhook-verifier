# AlgoVoi webhook-verifier — 8-implementation cross-validation attestation

**Date:** 2026-05-31  
**Package:** `algovoi-webhook-verifier` / `@algovoi/webhook-verifier` v0.1.0  
**Vectors:** 13 (5 valid + 8 invalid) in `vectors/`

## Result: 104/104 agreements (8 implementations × 13 vectors)

Every implementation reached byte-for-byte identical HMAC results and identical error-code verdicts across all 13 vectors.

## Implementations

| Language | Runtime | Result |
|---|---|---|
| Python | CPython 3.12.10 | 13/13 |
| TypeScript | Node.js 22 / Vitest 1.6.1 | 13/13 |
| Go | Go 1.26.1 | 13/13 |
| Rust | Rust 1.95.0 (stable-x86_64-pc-windows-gnu) | 13/13 |
| Java | OpenJDK 17.0.6 | 13/13 |
| PHP | PHP 8.4.20 (ZTS, ext-hash) | 13/13 |
| .NET | .NET 9.0.14 | 13/13 |
| Ruby | Ruby 3.4.9 (OpenSSL) | 13/13 |

## Vector corpus

| Vector | Category | Error code |
|---|---|---|
| v01_payment_confirmed_v1v2 | Valid | — |
| v02_payment_confirmed_v1_only | Valid | — |
| v03_different_secret | Valid | — |
| v04_minimal_payload | Valid | — |
| v05_unicode_payload | Valid (non-ASCII body) | — |
| i01_missing_signature | Invalid | MISSING_SIGNATURE |
| i02_malformed_signature | Invalid | MALFORMED_SIGNATURE |
| i03_stale_signature | Invalid | STALE_SIGNATURE |
| i04_invalid_signature_v1 | Invalid | INVALID_SIGNATURE |
| i05_wrong_secret | Invalid | INVALID_SIGNATURE |
| i06_tampered_body | Invalid | INVALID_SIGNATURE |
| i07_invalid_payload_not_json | Invalid | INVALID_PAYLOAD |
| i08_unknown_event_type | Invalid | UNKNOWN_EVENT_TYPE |

## Signing scheme under test

- Header: `X-AlgoVoi-Signature: t=<unix>,v1=<sha256hex>,v2=<sha384hex>`
- Signed payload: `{ts}.` (UTF-8) + raw body bytes
- v1: HMAC-SHA256(secret, signed\_payload)
- v2\_key: HKDF-SHA256(IKM=secret, salt=`algovoi-webhook-v2-pqc`, info=`hmac-sha384-outbound`, len=48)
- v2: HMAC-SHA384(v2\_key, signed\_payload)

All implementations use constant-time comparison for HMAC values.

## Verification

Reproduce with:

```bash
# Run all 8 languages
bash e2e/cross_validate.sh

# Individual languages
python -m pytest python/tests/test_vectors.py -v
cd typescript && npm test
go run implementations/go/verify_vectors.go vectors/
cargo run --manifest-path implementations/rust/Cargo.toml -- vectors/
cd implementations/java && javac VerifyVectors.java && java VerifyVectors ../../vectors
php implementations/php/verify_vectors.php vectors/
cd implementations/dotnet && dotnet run -- ../../vectors
ruby implementations/ruby/verify_vectors.rb vectors/
```
