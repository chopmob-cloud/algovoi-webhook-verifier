import { createHmac } from "crypto";
import { hkdfSync } from "crypto";
import * as fs from "fs";
import * as path from "path";
import { describe, it, expect, beforeEach, vi, afterEach } from "vitest";

import {
  verifyWebhook,
  WebhookVerificationError,
  DEFAULT_TOLERANCE,
  KNOWN_EVENT_TYPES,
  SIGNATURE_HEADER,
} from "../src/index.js";

// -------------------------------------------------------------------------- //
// Helpers                                                                     //
// -------------------------------------------------------------------------- //

const SECRET = "algvw_test_unit_secret";
const NOW = 1748650000; // fixed ts for all tests

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

function sign(secret: string, ts: number, body: Buffer): string {
  const sb = Buffer.from(secret, "utf8");
  const sp = Buffer.concat([Buffer.from(`${ts}.`), body]);
  const v1 = createHmac("sha256", sb).update(sp).digest("hex");
  const v2Key = deriveV2Key(sb);
  const v2 = createHmac("sha384", v2Key).update(sp).digest("hex");
  return `t=${ts},v1=${v1},v2=${v2}`;
}

function paymentBody(overrides: Record<string, unknown> = {}): Buffer {
  return Buffer.from(
    JSON.stringify({
      id: "evt_unit_001",
      type: "payment.confirmed",
      created: NOW,
      api_version: "2024-01-01",
      data: {},
      ...overrides,
    }),
    "utf8",
  );
}

function call(
  body?: Buffer,
  secret = SECRET,
  ts = NOW,
  extra: Record<string, unknown> = {},
) {
  const b = body ?? paymentBody();
  const header = sign(secret, ts, b);
  return verifyWebhook({
    payload: b,
    secret,
    signatureHeader: header,
    tolerance: 0,
    ...extra,
  });
}

// -------------------------------------------------------------------------- //
// Happy path                                                                  //
// -------------------------------------------------------------------------- //

describe("happy path", () => {
  it("returns parsed event", () => {
    const event = call();
    expect(event.type).toBe("payment.confirmed");
    expect(event.id).toBe("evt_unit_001");
  });

  it("accepts v1-only signature", () => {
    const body = paymentBody();
    const sb = Buffer.from(SECRET);
    const sp = Buffer.concat([Buffer.from(`${NOW}.`), body]);
    const v1 = createHmac("sha256", sb).update(sp).digest("hex");
    const event = verifyWebhook({
      payload: body,
      secret: SECRET,
      signatureHeader: `t=${NOW},v1=${v1}`,
      tolerance: 0,
    });
    expect(event.type).toBe("payment.confirmed");
  });

  it("validates v2 when requireV2=true", () => {
    const event = call(undefined, SECRET, NOW, { requireV2: true });
    expect(event.type).toBe("payment.confirmed");
  });

  it("accepts string payload", () => {
    const body = paymentBody();
    const header = sign(SECRET, NOW, body);
    const event = verifyWebhook({
      payload: body.toString("utf8"),
      secret: SECRET,
      signatureHeader: header,
      tolerance: 0,
    });
    expect(event.type).toBe("payment.confirmed");
  });

  it("trims whitespace from header", () => {
    const body = paymentBody();
    const header = "  " + sign(SECRET, NOW, body) + "  ";
    const event = verifyWebhook({
      payload: body,
      secret: SECRET,
      signatureHeader: header,
      tolerance: 0,
    });
    expect(event.type).toBe("payment.confirmed");
  });

  it("handles unicode body", () => {
    const body = Buffer.from(
      JSON.stringify({
        id: "evt_u_001",
        type: "payment.confirmed",
        created: NOW,
        api_version: "2024-01-01",
        data: { label: "café" },
      }),
      "utf8",
    );
    const header = sign(SECRET, NOW, body);
    const event = verifyWebhook({
      payload: body,
      secret: SECRET,
      signatureHeader: header,
      tolerance: 0,
    });
    expect((event.data as { label: string }).label).toBe("café");
  });
});

// -------------------------------------------------------------------------- //
// MISSING_SIGNATURE                                                           //
// -------------------------------------------------------------------------- //

describe("MISSING_SIGNATURE", () => {
  it.each(["", "   "])("empty header %j", (header) => {
    expect(() =>
      verifyWebhook({
        payload: paymentBody(),
        secret: SECRET,
        signatureHeader: header,
        tolerance: 0,
      }),
    ).toThrow(expect.objectContaining({ code: "MISSING_SIGNATURE" }));
  });
});

// -------------------------------------------------------------------------- //
// MALFORMED_SIGNATURE                                                         //
// -------------------------------------------------------------------------- //

describe("MALFORMED_SIGNATURE", () => {
  const bad = [
    "v1=abc123",
    "t=abc,v1=abc",
    "t=123,v2=abc",
    "t=123,v1=" + "a".repeat(63),
    "t=123,v1=" + "a".repeat(65),
    "t=123,v1=" + "g".repeat(64),
    "randomgarbage",
  ];
  it.each(bad)("rejects %j", (header) => {
    expect(() =>
      verifyWebhook({
        payload: paymentBody(),
        secret: SECRET,
        signatureHeader: header,
        tolerance: 0,
      }),
    ).toThrow(expect.objectContaining({ code: "MALFORMED_SIGNATURE" }));
  });
});

// -------------------------------------------------------------------------- //
// STALE_SIGNATURE                                                             //
// -------------------------------------------------------------------------- //

describe("STALE_SIGNATURE", () => {
  beforeEach(() => {
    vi.useFakeTimers();
    vi.setSystemTime(NOW * 1000); // Date.now() in ms
  });
  afterEach(() => vi.useRealTimers());

  it("rejects timestamp 600s old (tolerance 300)", () => {
    const oldTs = NOW - 600;
    const body = paymentBody();
    const header = sign(SECRET, oldTs, body);
    expect(() =>
      verifyWebhook({ payload: body, secret: SECRET, signatureHeader: header, tolerance: 300 }),
    ).toThrow(expect.objectContaining({ code: "STALE_SIGNATURE" }));
  });

  it("rejects future timestamp beyond tolerance", () => {
    const futureTs = NOW + 600;
    const body = paymentBody();
    const header = sign(SECRET, futureTs, body);
    expect(() =>
      verifyWebhook({ payload: body, secret: SECRET, signatureHeader: header, tolerance: 300 }),
    ).toThrow(expect.objectContaining({ code: "STALE_SIGNATURE" }));
  });

  it("tolerance=0 bypasses check", () => {
    const oldTs = NOW - 99999;
    const body = paymentBody();
    const header = sign(SECRET, oldTs, body);
    const event = verifyWebhook({ payload: body, secret: SECRET, signatureHeader: header, tolerance: 0 });
    expect(event.type).toBe("payment.confirmed");
  });
});

// -------------------------------------------------------------------------- //
// INVALID_SIGNATURE                                                           //
// -------------------------------------------------------------------------- //

describe("INVALID_SIGNATURE", () => {
  it("wrong secret", () => {
    const body = paymentBody();
    const header = sign("algvw_wrong_secret", NOW, body);
    expect(() =>
      verifyWebhook({ payload: body, secret: SECRET, signatureHeader: header, tolerance: 0 }),
    ).toThrow(expect.objectContaining({ code: "INVALID_SIGNATURE" }));
  });

  it("tampered body", () => {
    const body = paymentBody();
    const header = sign(SECRET, NOW, body);
    const tampered = Buffer.from(body.toString().replace("evt_unit_001", "evt_tampered"));
    expect(() =>
      verifyWebhook({ payload: tampered, secret: SECRET, signatureHeader: header, tolerance: 0 }),
    ).toThrow(expect.objectContaining({ code: "INVALID_SIGNATURE" }));
  });

  it("corrupted v1 hex", () => {
    const body = paymentBody();
    let header = sign(SECRET, NOW, body);
    header = header.slice(0, -1) + (header.slice(-1) !== "0" ? "0" : "1");
    expect(() =>
      verifyWebhook({ payload: body, secret: SECRET, signatureHeader: header, tolerance: 0 }),
    ).toThrow(expect.objectContaining({ code: "INVALID_SIGNATURE" }));
  });

  it("requireV2=true with v1-only header", () => {
    const body = paymentBody();
    const sb = Buffer.from(SECRET);
    const sp = Buffer.concat([Buffer.from(`${NOW}.`), body]);
    const v1 = createHmac("sha256", sb).update(sp).digest("hex");
    expect(() =>
      verifyWebhook({
        payload: body,
        secret: SECRET,
        signatureHeader: `t=${NOW},v1=${v1}`,
        tolerance: 0,
        requireV2: true,
      }),
    ).toThrow(expect.objectContaining({ code: "INVALID_SIGNATURE" }));
  });
});

// -------------------------------------------------------------------------- //
// INVALID_PAYLOAD                                                             //
// -------------------------------------------------------------------------- //

describe("INVALID_PAYLOAD", () => {
  it("not JSON", () => {
    const body = Buffer.from("not-json");
    const header = sign(SECRET, NOW, body);
    expect(() =>
      verifyWebhook({ payload: body, secret: SECRET, signatureHeader: header, tolerance: 0 }),
    ).toThrow(expect.objectContaining({ code: "INVALID_PAYLOAD" }));
  });

  it("JSON array root", () => {
    const body = Buffer.from('["a","b"]');
    const header = sign(SECRET, NOW, body);
    expect(() =>
      verifyWebhook({ payload: body, secret: SECRET, signatureHeader: header, tolerance: 0 }),
    ).toThrow(expect.objectContaining({ code: "INVALID_PAYLOAD" }));
  });

  it("truncated JSON", () => {
    const body = Buffer.from('{"type":"payment.confirmed"');
    const header = sign(SECRET, NOW, body);
    expect(() =>
      verifyWebhook({ payload: body, secret: SECRET, signatureHeader: header, tolerance: 0 }),
    ).toThrow(expect.objectContaining({ code: "INVALID_PAYLOAD" }));
  });
});

// -------------------------------------------------------------------------- //
// UNKNOWN_EVENT_TYPE                                                          //
// -------------------------------------------------------------------------- //

describe("UNKNOWN_EVENT_TYPE", () => {
  const unknownTypes = ["refund.issued", "payment.failed", "mandate.cancelled", null, ""];
  it.each(unknownTypes)("rejects type=%j", (eventType) => {
    const body = Buffer.from(
      JSON.stringify({
        id: "evt_unk",
        type: eventType,
        created: NOW,
        api_version: "2024-01-01",
        data: {},
      }),
    );
    const header = sign(SECRET, NOW, body);
    expect(() =>
      verifyWebhook({ payload: body, secret: SECRET, signatureHeader: header, tolerance: 0 }),
    ).toThrow(expect.objectContaining({ code: "UNKNOWN_EVENT_TYPE" }));
  });
});

// -------------------------------------------------------------------------- //
// Error object shape                                                          //
// -------------------------------------------------------------------------- //

describe("error object", () => {
  it("has code, message, and name", () => {
    expect(() =>
      verifyWebhook({ payload: paymentBody(), secret: SECRET, signatureHeader: "", tolerance: 0 }),
    ).toThrow(
      expect.objectContaining({
        code: "MISSING_SIGNATURE",
        name: "WebhookVerificationError",
      }),
    );
  });

  it("instanceof WebhookVerificationError", () => {
    try {
      verifyWebhook({ payload: paymentBody(), secret: SECRET, signatureHeader: "", tolerance: 0 });
    } catch (err) {
      expect(err).toBeInstanceOf(WebhookVerificationError);
    }
  });
});

// -------------------------------------------------------------------------- //
// Cross-validation vectors                                                    //
// -------------------------------------------------------------------------- //

const VECTORS_ROOT = path.join(__dirname, "../../vectors");

function loadVectors(subdir: string) {
  const dir = path.join(VECTORS_ROOT, subdir);
  if (!fs.existsSync(dir)) return [];
  return fs.readdirSync(dir).filter((f) => f.endsWith(".json")).map((f) => path.join(dir, f));
}

describe("valid vectors", () => {
  const fixtures = loadVectors("valid");
  it.each(fixtures)("%s", (fixturePath) => {
    const fixture = JSON.parse(fs.readFileSync(fixturePath, "utf8"));
    const body = Buffer.from(fixture.body, "utf8");
    const event = verifyWebhook({
      payload: body,
      secret: fixture.secret,
      signatureHeader: fixture.signature_header,
      tolerance: 0,
    });
    expect(event.type).toBe("payment.confirmed");
  });
});

describe("invalid vectors", () => {
  const fixtures = loadVectors("invalid");
  it.each(fixtures)("%s", (fixturePath) => {
    const fixture = JSON.parse(fs.readFileSync(fixturePath, "utf8"));
    const body = Buffer.from(fixture.body, "utf8");
    const tolerance = fixture.tolerance ?? 0;
    const fakeNow = fixture.fake_now;

    const run = () =>
      verifyWebhook({
        payload: body,
        secret: fixture.secret,
        signatureHeader: fixture.signature_header,
        tolerance,
      });

    if (fakeNow !== undefined) {
      vi.useFakeTimers();
      vi.setSystemTime(fakeNow * 1000);
    }
    try {
      expect(run).toThrow(
        expect.objectContaining({ code: fixture.error_code }),
      );
    } finally {
      if (fakeNow !== undefined) vi.useRealTimers();
    }
  });
});
