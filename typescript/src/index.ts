/**
 * AlgoVoi webhook signature verifier — v1 (HMAC-SHA256) + v2 (HKDF-SHA256 / HMAC-SHA384).
 *
 * @example
 * ```ts
 * import { verifyWebhook, WebhookVerificationError } from "@algovoi/webhook-verifier";
 *
 * try {
 *   const event = verifyWebhook({
 *     payload: req.body,           // raw Buffer
 *     secret: process.env.ALGOVOI_WEBHOOK_SECRET!,
 *     signatureHeader: req.headers["x-algovoi-signature"] as string,
 *   });
 *   console.log(event.type);       // "payment.confirmed"
 * } catch (err) {
 *   if (err instanceof WebhookVerificationError) {
 *     console.error(err.code, err.message);
 *   }
 * }
 * ```
 */

import { createHmac, timingSafeEqual } from "crypto";
import { hkdfSync } from "crypto";

// -------------------------------------------------------------------------- //
// Types                                                                       //
// -------------------------------------------------------------------------- //

export type ErrorCode =
  | "MISSING_SIGNATURE"
  | "MALFORMED_SIGNATURE"
  | "STALE_SIGNATURE"
  | "INVALID_SIGNATURE"
  | "INVALID_PAYLOAD"
  | "UNKNOWN_EVENT_TYPE";

export const ERROR_CODES: ReadonlySet<ErrorCode> = new Set<ErrorCode>([
  "MISSING_SIGNATURE",
  "MALFORMED_SIGNATURE",
  "STALE_SIGNATURE",
  "INVALID_SIGNATURE",
  "INVALID_PAYLOAD",
  "UNKNOWN_EVENT_TYPE",
]);

export interface WebhookEvent {
  id: string;
  type: string;
  created: number;
  api_version: string;
  data: Record<string, unknown>;
}

export interface VerifyOptions {
  /** Raw request body bytes. */
  payload: Buffer | Uint8Array | string;
  /** Tenant webhook signing secret (``algvw_*``). */
  secret: string;
  /** Value of the ``X-AlgoVoi-Signature`` header. */
  signatureHeader: string;
  /**
   * Maximum age of a valid signature in seconds. Default: 300.
   * Pass 0 to disable (test environments only).
   */
  tolerance?: number;
  /**
   * If true, the v2 signature component must be present and valid.
   * Default: false (v2 validated when present, accepted when absent).
   */
  requireV2?: boolean;
}

// -------------------------------------------------------------------------- //
// Error                                                                       //
// -------------------------------------------------------------------------- //

export class WebhookVerificationError extends Error {
  readonly code: ErrorCode;

  constructor(code: ErrorCode, message: string) {
    super(message);
    this.name = "WebhookVerificationError";
    this.code = code;
    // Maintain proper stack trace in V8
    if (Error.captureStackTrace) {
      Error.captureStackTrace(this, WebhookVerificationError);
    }
  }
}

// -------------------------------------------------------------------------- //
// Constants                                                                   //
// -------------------------------------------------------------------------- //

export const SIGNATURE_HEADER = "X-AlgoVoi-Signature";
export const DEFAULT_TOLERANCE = 300;
export const KNOWN_EVENT_TYPES: ReadonlySet<string> = new Set(["payment.confirmed"]);

const SIG_RE =
  /^t=(?<ts>\d+),v1=(?<v1>[0-9a-f]{64})(?:,v2=(?<v2>[0-9a-f]{96}))?$/;

// -------------------------------------------------------------------------- //
// Internal helpers                                                            //
// -------------------------------------------------------------------------- //

function deriveV2Key(secretBytes: Buffer): Buffer {
  return Buffer.from(
    hkdfSync(
      "sha256",
      secretBytes,
      Buffer.from("algovoi-webhook-v2-pqc"),
      Buffer.from("hmac-sha384-outbound"),
      48,
    ),
  );
}

function computeSigs(
  secret: string,
  ts: number,
  body: Buffer,
): { v1: string; v2: string } {
  const secretBytes = Buffer.from(secret, "utf8");
  const tsPrefix = Buffer.from(`${ts}.`, "utf8");
  const signedPayload = Buffer.concat([tsPrefix, body]);

  const v1 = createHmac("sha256", secretBytes)
    .update(signedPayload)
    .digest("hex");

  const v2Key = deriveV2Key(secretBytes);
  const v2 = createHmac("sha384", v2Key)
    .update(signedPayload)
    .digest("hex");

  return { v1, v2 };
}

function timingSafeCompareHex(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  return timingSafeEqual(Buffer.from(a, "hex"), Buffer.from(b, "hex"));
}

// -------------------------------------------------------------------------- //
// Public API                                                                  //
// -------------------------------------------------------------------------- //

/**
 * Verify an AlgoVoi webhook signature and return the parsed event.
 *
 * @throws {WebhookVerificationError} on any verification failure.
 */
export function verifyWebhook(options: VerifyOptions): WebhookEvent {
  const {
    payload,
    secret,
    signatureHeader,
    tolerance = DEFAULT_TOLERANCE,
    requireV2 = false,
  } = options;

  // 1. Presence check
  const trimmedHeader = signatureHeader.trim();
  if (!trimmedHeader) {
    throw new WebhookVerificationError(
      "MISSING_SIGNATURE",
      "X-AlgoVoi-Signature header is absent",
    );
  }

  // 2. Parse header
  const match = SIG_RE.exec(trimmedHeader);
  if (!match || !match.groups) {
    throw new WebhookVerificationError(
      "MALFORMED_SIGNATURE",
      `Signature header does not match expected format t=<unix>,v1=<sha256hex>[,v2=<sha384hex>]: ${signatureHeader}`,
    );
  }

  const ts = parseInt(match.groups.ts, 10);
  const receivedV1 = match.groups.v1;
  const receivedV2: string | undefined = match.groups.v2;

  // 3. Staleness check
  if (tolerance > 0) {
    const age = Math.abs(Math.floor(Date.now() / 1000) - ts);
    if (age > tolerance) {
      throw new WebhookVerificationError(
        "STALE_SIGNATURE",
        `Signature timestamp ${ts} is ${age}s old (tolerance ${tolerance}s)`,
      );
    }
  }

  // 4. HMAC computation
  const body =
    typeof payload === "string"
      ? Buffer.from(payload, "utf8")
      : Buffer.from(payload);

  const { v1: expectedV1, v2: expectedV2 } = computeSigs(secret, ts, body);

  // 5. Comparison
  const v1Ok = timingSafeCompareHex(receivedV1, expectedV1);

  let v2Ok: boolean;
  if (receivedV2 !== undefined) {
    v2Ok = timingSafeCompareHex(receivedV2, expectedV2);
  } else {
    v2Ok = !requireV2;
  }

  if (!v1Ok || !v2Ok) {
    throw new WebhookVerificationError(
      "INVALID_SIGNATURE",
      "One or more signature components did not match",
    );
  }

  // 6. Payload parse
  let event: unknown;
  try {
    event = JSON.parse(
      typeof payload === "string" ? payload : body.toString("utf8"),
    );
  } catch (err) {
    throw new WebhookVerificationError(
      "INVALID_PAYLOAD",
      `Payload is not valid JSON: ${(err as Error).message}`,
    );
  }

  if (typeof event !== "object" || event === null || Array.isArray(event)) {
    throw new WebhookVerificationError(
      "INVALID_PAYLOAD",
      "Payload root must be a JSON object",
    );
  }

  // 7. Event-type check
  const eventType = (event as Record<string, unknown>).type;
  if (!KNOWN_EVENT_TYPES.has(eventType as string)) {
    throw new WebhookVerificationError(
      "UNKNOWN_EVENT_TYPE",
      `Unrecognised event type: ${JSON.stringify(eventType)}`,
    );
  }

  return event as WebhookEvent;
}
