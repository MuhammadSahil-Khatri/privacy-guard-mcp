import { test } from "node:test";
import assert from "node:assert/strict";
import { scan, redact, restore, MAX_INPUT_CHARS } from "../src/detect.js";

test("clean text yields no findings", () => {
  const text = "The meeting is on 2026-10-16 at room 42. Revenue grew 12% in Q3.";
  assert.equal(scan(text).length, 0);
  assert.equal(redact(text).redacted, text);
});

test("detects and redacts email", () => {
  const r = redact("Contact sara@example.com today");
  assert.equal(r.redacted, "Contact [REDACTED_EMAIL] today");
  assert.deepEqual(r.counts, { EMAIL: 1 });
});

test("detects international and formatted phone numbers", () => {
  assert.equal(scan("Call +44 7700 900123 now")[0]?.type, "PHONE");
  assert.equal(scan("Call (415) 637-6526 now")[0]?.type, "PHONE");
  assert.equal(scan("Call 0300-1234567 now")[0]?.type, "PHONE");
});

test("does not flag ISO dates or short numbers as phones", () => {
  assert.equal(scan("Shipped 2026-10-16, order 12345").length, 0);
});

test("credit card requires a valid Luhn checksum", () => {
  assert.equal(scan("Card 4111 1111 1111 1111")[0]?.type, "CARD");
  assert.equal(scan("Card 4111 1111 1111 1112").some((f) => f.type === "CARD"), false);
});

test("detects secrets: AWS, GitHub, JWT, API keys, private keys", () => {
  const aws = "AKIAIOSFODNN7EXAMPLE";
  const gh = "ghp_" + "a".repeat(36);
  const jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abcdefghijklmnop";
  const key = "sk-" + "x".repeat(24);
  const pem = "-----BEGIN RSA PRIVATE KEY-----\nMIIabc\n-----END RSA PRIVATE KEY-----";
  const types = scan([aws, gh, jwt, key, pem].join("\n")).map((f) => f.type);
  assert.deepEqual(types, ["AWS_KEY", "GITHUB_TOKEN", "JWT", "API_KEY", "PRIVATE_KEY"]);
});

test("scan never returns raw values", () => {
  const f = scan("mail sara.whitfield@example.com")[0];
  assert.ok(!f.preview.includes("whitfield"));
  assert.ok(!JSON.stringify(f).includes("sara.whitfield@example.com"));
});

test("overlaps: card number is not also reported as a phone", () => {
  const f = scan("Card 4111 1111 1111 1111");
  assert.equal(f.length, 1);
  assert.equal(f[0].type, "CARD");
});

test("custom patterns work and are validated", () => {
  const r = redact("Employee EMP-123456 left", { custom: [{ name: "EMPLOYEE_ID", pattern: "EMP-\\d{6}" }] });
  assert.equal(r.redacted, "Employee [REDACTED_EMPLOYEE_ID] left");
  assert.throws(() => scan("x", { custom: [{ name: "bad name", pattern: "x" }] }));
});

test("type filter limits detection", () => {
  const r = redact("a@b.com and 4111 1111 1111 1111", { types: ["EMAIL"] });
  assert.equal(r.redacted, "[REDACTED_EMAIL] and 4111 1111 1111 1111");
});

test("reversible redaction round-trips and reuses placeholders", () => {
  const original = "Email sara@example.com, again sara@example.com, cc bob@example.com";
  const r = redact(original, { reversible: true });
  assert.equal(r.redacted, "Email [EMAIL_1], again [EMAIL_1], cc [EMAIL_2]");
  assert.equal(restore(r.redacted, r.map!).text, original);
});

test("restore leaves unknown placeholders alone", () => {
  assert.deepEqual(restore("Hi [EMAIL_9]", {}), { text: "Hi [EMAIL_9]", restored: 0 });
});

test("oversized input is rejected", () => {
  assert.throws(() => scan("a".repeat(MAX_INPUT_CHARS + 1)), /too large/);
});

test("redaction is non-reversible by default (no map returned)", () => {
  assert.equal(redact("a@b.com").map, undefined);
});
