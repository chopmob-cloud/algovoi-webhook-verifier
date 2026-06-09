# algovoi-webhook-verifier / @algovoi/webhook-verifier

[![PyPI version](https://img.shields.io/pypi/v/algovoi-webhook-verifier.svg)](https://pypi.org/project/algovoi-webhook-verifier/)
[![npm version](https://img.shields.io/npm/v/@algovoi/webhook-verifier.svg)](https://www.npmjs.com/package/@algovoi/webhook-verifier)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Vectors](https://img.shields.io/badge/vectors-13%2F13-brightgreen)](vectors/)
[![Cross-validation](https://img.shields.io/badge/cross--validation-104%2F104%20%288%20langs%29-brightgreen)](_attestations/2026-05-31-8-impl-cross-validation.md)

Cryptographic verifier for [AlgoVoi](https://algovoi.co.uk) webhook signatures. Validates the `X-AlgoVoi-Signature` header produced by the AlgoVoi gateway using:

- **v1** — HMAC-SHA256 with the tenant signing secret
- **v2** — HKDF-SHA256 key derivation + HMAC-SHA384 (post-quantum preparedness)

Offline-capable. No AlgoVoi infrastructure trust required. 13 shared cross-validation vectors (5 valid + 8 invalid) covering all error modes.

---

## Install

```bash
# Python
pip install algovoi-webhook-verifier

# TypeScript / Node.js
npm install @algovoi/webhook-verifier
```

---

## Quick start

### Python (Flask)

```python
from flask import Flask, request
from algovoi_webhook_verifier import verify_webhook, WebhookVerificationError

app = Flask(__name__)

@app.route("/webhook", methods=["POST"])
def webhook():
    try:
        event = verify_webhook(
            payload=request.get_data(),
            secret=os.environ["ALGOVOI_WEBHOOK_SECRET"],
            signature_header=request.headers.get("X-AlgoVoi-Signature", ""),
        )
    except WebhookVerificationError as e:
        return {"error": e.code}, 400

    if event["type"] == "payment.confirmed":
        data = event["data"]
        print(f"Payment {data['resource_id']} confirmed on {data['chain']}")

    return {"received": True}, 200
```

### TypeScript (Express)

```typescript
import express from "express";
import { verifyWebhook, WebhookVerificationError } from "@algovoi/webhook-verifier";

const app = express();
app.use(express.raw({ type: "application/json" }));

app.post("/webhook", (req, res) => {
  try {
    const event = verifyWebhook({
      payload: req.body,
      secret: process.env.ALGOVOI_WEBHOOK_SECRET!,
      signatureHeader: req.headers["x-algovoi-signature"] as string,
    });

    if (event.type === "payment.confirmed") {
      const { resource_id, chain } = event.data as { resource_id: string; chain: string };
      console.log(`Payment ${resource_id} confirmed on ${chain}`);
    }

    res.json({ received: true });
  } catch (err) {
    if (err instanceof WebhookVerificationError) {
      res.status(400).json({ error: err.code });
    } else {
      res.status(500).end();
    }
  }
});
```

---

## Verification steps

| Step | Check |
|---|---|
| 1 | Header present |
| 2 | Header matches `t=<unix>,v1=<sha256hex>[,v2=<sha384hex>]` |
| 3 | Timestamp within tolerance (default 300 s) |
| 4 | v1 = HMAC-SHA256(secret, `"{ts}." + raw_body`) |
| 5 | v2 = HMAC-SHA384(HKDF-SHA256(secret), `"{ts}." + raw_body`) — validated when present |
| 6 | Body is valid JSON object |
| 7 | `type` field is a known event type |

---

## Error codes

| Code | Cause |
|---|---|
| `MISSING_SIGNATURE` | `X-AlgoVoi-Signature` header absent or blank |
| `MALFORMED_SIGNATURE` | Header does not match expected format |
| `STALE_SIGNATURE` | Timestamp outside the tolerance window |
| `INVALID_SIGNATURE` | v1 or v2 HMAC mismatch |
| `INVALID_PAYLOAD` | Body is not a valid JSON object |
| `UNKNOWN_EVENT_TYPE` | `type` field not in known event set |

---

## API reference

### Python

```python
from algovoi_webhook_verifier import verify_webhook, WebhookVerificationError

event = verify_webhook(
    payload: bytes,            # raw request body
    secret: str,               # algvw_* signing secret
    signature_header: str,     # X-AlgoVoi-Signature value
    tolerance: int = 300,      # max age in seconds; 0 to disable
    require_v2: bool = False,  # require v2 component to be present
) -> dict
```

### TypeScript

```typescript
import { verifyWebhook, WebhookVerificationError, VerifyOptions, WebhookEvent } from "@algovoi/webhook-verifier";

const event: WebhookEvent = verifyWebhook({
  payload: Buffer | Uint8Array | string,
  secret: string,
  signatureHeader: string,
  tolerance?: number,   // default 300; 0 to disable
  requireV2?: boolean,  // default false
});
```

---

## Cross-validation vectors

13 fixtures under `vectors/` (5 valid, 8 invalid). Each is self-contained — includes the secret, raw body, and header so any language can verify the implementation.

| Vector | Description |
|---|---|
| `v01_payment_confirmed_v1v2` | Valid v1+v2, `payment.confirmed` |
| `v02_payment_confirmed_v1_only` | Valid v1-only (v2 absent) |
| `v03_different_secret` | Valid with second secret |
| `v04_minimal_payload` | Valid with minimal `data: {}` |
| `v05_unicode_payload` | Valid with non-ASCII characters |
| `i01_missing_signature` | `MISSING_SIGNATURE` |
| `i02_malformed_signature` | `MALFORMED_SIGNATURE` |
| `i03_stale_signature` | `STALE_SIGNATURE` |
| `i04_invalid_signature_v1` | `INVALID_SIGNATURE` — corrupted v1 |
| `i05_wrong_secret` | `INVALID_SIGNATURE` — wrong secret |
| `i06_tampered_body` | `INVALID_SIGNATURE` — body modified |
| `i07_invalid_payload_not_json` | `INVALID_PAYLOAD` |
| `i08_unknown_event_type` | `UNKNOWN_EVENT_TYPE` |

Regenerate:

```bash
python vectors/generate_vectors.py
```

---

## Test results

| Implementation | Tests | Result |
|---|---|---|
| Python unit | 34 | 34/34 |
| Python vectors | 13 | 13/13 |
| TypeScript unit | 32 | 32/32 |
| TypeScript vectors | 13 | 13/13 |

**Python 47/47 · TypeScript 45/45**

### 8-language cross-validation

104/104 agreements across all 8 implementations × 13 vectors. See [`_attestations/2026-05-31-8-impl-cross-validation.md`](_attestations/2026-05-31-8-impl-cross-validation.md).

| Language | Result |
|---|---|
| Python | 13/13 |
| TypeScript | 13/13 |
| Go | 13/13 |
| Rust | 13/13 |
| Java | 13/13 |
| PHP | 13/13 |
| .NET | 13/13 |
| Ruby | 13/13 |

---

## Supported event types

| Type | Description |
|---|---|
| `payment.confirmed` | On-chain payment confirmed by the AlgoVoi facilitator |

---

## Related packages

| Package | Purpose |
|---|---|
| [algovoi-receipt-verifier](https://docs.algovoi.co.uk/receipt-verifier) | Verify JWS compliance receipts |
| [algovoi-audit-verifier](https://docs.algovoi.co.uk/audit-verifier) | Verify audit chain bundles |
| [algovoi-substrate](https://docs.algovoi.co.uk/canonicalisation-substrate) | JCS canonicalisation substrate |

---

## License

Apache 2.0. See [LICENSE](LICENSE).
## Attribution

This package is Apache-2.0. Use it freely and build whatever you are building on top of it. The only ask is the one the licence already makes: keep the NOTICE, and name who authored the substrate. To attribute it in your own product, add this to your NOTICE file:

```
This product includes the AlgoVoi substrate,
authored by Christopher Hopley / AlgoVoi (chopmob-cloud), Apache-2.0.
https://docs.algovoi.co.uk/canonicalisation-substrate
```

The full invitation is at https://docs.algovoi.co.uk/canonicalisation-substrate#adopt-the-substrate
