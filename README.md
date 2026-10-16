# Privacy Guard MCP

A small, local, dependency-light [MCP](https://modelcontextprotocol.io) server that detects and redacts sensitive data **before** it reaches downstream AI tools.

> Independent proof of concept. Not an official Secure AI project.

- Runs fully offline over stdio. No network calls, no API keys, no telemetry.
- Detection core (`src/detect.ts`) is pure TypeScript with zero dependencies and is unit tested.
- Logs go to stderr and contain **counts and entity types only**, never input text or values.

## Tools

| Tool | What it does |
| --- | --- |
| `scan_sensitive_data` | Finds emails, phones, payment cards (Luhn-checked), US SSNs, IPv4, API keys, AWS/GitHub tokens, JWTs, bearer tokens, private keys, plus custom patterns. Returns type, position and a **masked preview**, never raw values. |
| `redact_sensitive_data` | Replaces findings with `[REDACTED_EMAIL]` etc. With `reversible: true` it uses `[EMAIL_1]` style placeholders and returns a map. |
| `restore_sensitive_data` | Puts originals back using that map, for a trusted local step. |

## Quick start

```bash
npm install
npm run build
npm test
npm run inspect      # opens MCP Inspector against the built server
```

In MCP Inspector, call `redact_sensitive_data` with:

```json
{ "text": "Email sara@example.com or call +44 7700 900123. Card 4111 1111 1111 1111." }
```

Expected `redacted`:

```
Email [REDACTED_EMAIL] or call [REDACTED_PHONE]. Card [REDACTED_CARD].
```

### Use from an MCP client (Claude Desktop / Cursor)

```json
{
  "mcpServers": {
    "privacy-guard": {
      "command": "node",
      "args": ["/absolute/path/to/privacy-guard-mcp/dist/server.js"]
    }
  }
}
```

### Custom patterns

```bash
export PRIVACY_GUARD_PATTERNS='[{"name":"EMPLOYEE_ID","pattern":"EMP-\\d{6}"}]'
```

Names must be `UPPER_SNAKE_CASE`; patterns are capped at 300 chars; input is capped at 100,000 chars to limit regex cost.

## Manual test cases

| Input | Expect |
| --- | --- |
| `Revenue grew 12% on 2026-10-16` | no findings |
| `sara@example.com` | `EMAIL` |
| `+44 7700 900123`, `(415) 637-6526` | `PHONE` |
| `4111 1111 1111 1111` | `CARD` |
| `4111 1111 1111 1112` (bad checksum) | no `CARD` |
| `AKIAIOSFODNN7EXAMPLE` | `AWS_KEY` |
| PEM private key block | `PRIVATE_KEY` |
| 100,001 characters | error: input too large |

Automated versions live in `test/detect.test.ts`.

## Design notes

- **Mask, don't echo.** `scan` never returns the matched value, so even the scan result is safe to forward.
- **Overlap resolution.** Higher-priority detectors win (a card number is not also reported as a phone).
- **Reversible mode is opt-in.** The map holds the real values, so the caller is responsible for keeping it local.
- **stdout is protocol-only.** All logging is on stderr.

## Limitations (please read)

- Regex detection is a floor, not a guarantee. It does **not** detect personal names, street addresses, or free-form context ("my account is 40718842"). Real coverage needs NER or model-based detection.
- Calling a tool manually does not protect an agent's traffic. Protection requires placing redaction in the actual execution path (gateway/proxy/SDK wrapper), where the agent cannot skip it.
- No policy engine, approvals or audit trail.

## How this relates to Secure AI

[Secure AI](https://secureai.one/developers/docs) already offers hosted redaction/restore (including an MCP server at `/mcp`), an SDK with `hide`/`reveal`/`check`, and a policy/approval layer. This project is a small **local, offline** complement: a first-pass filter for text that must not leave the machine at all, and a reference for how a minimal MCP privacy tool is structured. A natural next step would be an optional adapter that sends residual text to a stronger hosted detector.