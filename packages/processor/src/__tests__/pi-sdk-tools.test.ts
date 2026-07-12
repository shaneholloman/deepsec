import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { AuthStorage, ModelRegistry } from "@earendil-works/pi-coding-agent";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  createPiReadOnlyToolDefinitions,
  resolvePiModelWithDynamicGateway,
} from "../agents/pi-sdk.js";

describe("Pi read-only tools", () => {
  let root: string;
  let outside: string;

  beforeEach(() => {
    root = mkdtempSync(path.join(tmpdir(), "deepsec-pi-root-"));
    outside = path.join(mkdtempSync(path.join(tmpdir(), "deepsec-pi-outside-")), "secret.txt");
    writeFileSync(path.join(root, "inside.ts"), "export const ok = true;\n");
    writeFileSync(outside, "do not read me\n");
  });

  afterEach(() => {
    rmSync(root, { recursive: true, force: true });
    rmSync(path.dirname(outside), { recursive: true, force: true });
  });

  function tool(name: string) {
    const found = createPiReadOnlyToolDefinitions(root).find((t) => t.name === name);
    if (!found) throw new Error(`missing tool ${name}`);
    return found as any;
  }

  it("allows reads inside the project root", async () => {
    const result = await tool("read").execute("read-1", { path: "inside.ts" });
    expect(result.content[0].text).toContain("export const ok");
  });

  it("rejects reads outside the project root", async () => {
    await expect(tool("read").execute("read-1", { path: outside })).rejects.toThrow(
      /Path escapes project root/,
    );
  });

  it("implements find without relying on external fd downloads", async () => {
    const result = await tool("find").execute("find-1", { pattern: "*.ts" });
    expect(result.content[0].text).toContain("inside.ts");
  });
});

describe("Pi model resolution", () => {
  const KEYS = [
    "AI_GATEWAY_API_KEY",
    "VERCEL_OIDC_TOKEN",
    "OPENAI_API_KEY",
    "OPENAI_BASE_URL",
    "ANTHROPIC_AUTH_TOKEN",
    "ANTHROPIC_API_KEY",
    "ANTHROPIC_BASE_URL",
  ] as const;
  const originalEnv = Object.fromEntries(KEYS.map((key) => [key, process.env[key]]));
  const originalFetch = globalThis.fetch;

  afterEach(() => {
    for (const key of KEYS) {
      const value = originalEnv[key];
      if (value === undefined) delete process.env[key];
      else process.env[key] = value;
    }
    globalThis.fetch = originalFetch;
  });

  it("registers missing Vercel AI Gateway model ids without fetching the catalog", async () => {
    delete process.env.AI_GATEWAY_API_KEY;
    process.env.VERCEL_OIDC_TOKEN = "oidc_test";
    process.env.OPENAI_API_KEY = "oidc_test";
    process.env.OPENAI_BASE_URL = "https://ai-gateway.vercel.sh/v1";
    let called = false;
    globalThis.fetch = async () => {
      called = true;
      return new Response(JSON.stringify({ data: [] }), { status: 200 });
    };

    const registry = ModelRegistry.inMemory(AuthStorage.inMemory());
    const model = await resolvePiModelWithDynamicGateway(registry, "xai/grok-4.5", {});

    expect(model.provider).toBe("vercel-ai-gateway");
    expect(model.id).toBe("xai/grok-4.5");
    expect(model.name).toBe("xai/grok-4.5");
    expect(model.reasoning).toBe(true);
    expect(model.input).toEqual(["text", "image"]);
    expect(model.contextWindow).toBe(128000);
    expect(model.maxTokens).toBe(32000);
    expect(model.cost.input).toBe(0);
    expect(called).toBe(false);
  });

  it("does not register Gateway models for explicit custom provider overrides", async () => {
    process.env.AI_GATEWAY_API_KEY = "vck_test";
    process.env.OPENAI_BASE_URL = "https://ai-gateway.vercel.sh/v1";
    let called = false;
    globalThis.fetch = async () => {
      called = true;
      return new Response(JSON.stringify({ data: [] }), { status: 200 });
    };

    const registry = ModelRegistry.inMemory(AuthStorage.inMemory());
    await expect(
      resolvePiModelWithDynamicGateway(registry, "xai/grok-4.5", {
        aiProvider: "xai",
      }),
    ).rejects.toThrow(/Pi model not found: xai\/grok-4\.5/);
    expect(called).toBe(false);
  });
});
