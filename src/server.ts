#!/usr/bin/env node
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import { scan, redact, restore, MAX_INPUT_CHARS, type CustomPattern } from "./detect.js";

/**
 * Logging rule: stdout belongs to the MCP protocol, so logs go to stderr,
 * and logs only ever contain counts and entity types, never input or values.
 */
const log = (msg: string) => console.error(`[privacy-guard] ${msg}`);

function loadCustomPatterns(): CustomPattern[] {
  const raw = process.env.PRIVACY_GUARD_PATTERNS;
  if (!raw) return [];
  try {
    const parsed = z
      .array(z.object({ name: z.string(), pattern: z.string(), flags: z.string().optional() }))
      .parse(JSON.parse(raw));
    log(`loaded ${parsed.length} custom pattern(s)`);
    return parsed;
  } catch {
    // Do not echo the raw env value: it may contain internal naming.
    log("PRIVACY_GUARD_PATTERNS is invalid JSON or wrong shape; ignoring custom patterns");
    return [];
  }
}

const custom = loadCustomPatterns();

const server = new McpServer({ name: "privacy-guard-mcp", version: "0.1.0" });

const asText = (obj: unknown) => ({ content: [{ type: "text" as const, text: JSON.stringify(obj, null, 2) }] });
const asError = (e: unknown) => ({
  isError: true,
  content: [{ type: "text" as const, text: e instanceof Error ? e.message : "Unknown error" }],
});

const textInput = z.string().min(1).max(MAX_INPUT_CHARS).describe("The text to inspect");
const typesInput = z
  .array(z.string())
  .optional()
  .describe("Optional allow-list of entity types, e.g. ['EMAIL','CARD']. Default: all.");

server.registerTool(
  "scan_sensitive_data",
  {
    title: "Scan for sensitive data",
    description:
      "Detects emails, phone numbers, payment cards, SSNs, IPv4 addresses, API keys, tokens, private keys " +
      "and configured custom patterns. Returns types, positions and masked previews only, never raw values.",
    inputSchema: { text: textInput, types: typesInput },
    annotations: { readOnlyHint: true, idempotentHint: true, openWorldHint: false },
  },
  async ({ text, types }) => {
    try {
      const findings = scan(text, { custom, types });
      const byType: Record<string, number> = {};
      for (const f of findings) byType[f.type] = (byType[f.type] ?? 0) + 1;
      log(`scan: ${findings.length} finding(s) ${JSON.stringify(byType)}`);
      return asText({ sensitive: findings.length > 0, total: findings.length, counts: byType, findings });
    } catch (e) {
      log("scan: error");
      return asError(e);
    }
  },
);

server.registerTool(
  "redact_sensitive_data",
  {
    title: "Redact sensitive data",
    description:
      "Replaces sensitive values with placeholders such as [REDACTED_EMAIL]. Call this on any text BEFORE " +
      "sending it to another tool or model. Set reversible=true to get indexed placeholders ([EMAIL_1]) " +
      "and a map you can later pass to restore_sensitive_data.",
    inputSchema: {
      text: textInput,
      types: typesInput,
      reversible: z.boolean().optional().describe("Return a placeholder->original map. Default false."),
    },
    annotations: { readOnlyHint: true, idempotentHint: true, openWorldHint: false },
  },
  async ({ text, types, reversible }) => {
    try {
      const result = redact(text, { custom, types, reversible });
      log(`redact: ${result.total} replacement(s) ${JSON.stringify(result.counts)} reversible=${!!reversible}`);
      return asText(result);
    } catch (e) {
      log("redact: error");
      return asError(e);
    }
  },
);

server.registerTool(
  "restore_sensitive_data",
  {
    title: "Restore redacted values",
    description:
      "Puts original values back into text that was redacted with reversible=true. Use only in a trusted " +
      "local step; never send the restored output to an untrusted tool.",
    inputSchema: {
      text: textInput,
      map: z.record(z.string()).describe("The map returned by redact_sensitive_data"),
    },
    annotations: { readOnlyHint: true, idempotentHint: true, openWorldHint: false },
  },
  async ({ text, map }) => {
    try {
      const r = restore(text, map);
      log(`restore: ${r.restored} placeholder(s) restored`);
      return asText(r);
    } catch (e) {
      log("restore: error");
      return asError(e);
    }
  },
);

async function main() {
  await server.connect(new StdioServerTransport());
  log("ready on stdio");
}

main().catch(() => {
  log("fatal startup error");
  process.exit(1);
});
