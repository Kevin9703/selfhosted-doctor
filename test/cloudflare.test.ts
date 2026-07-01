import { describe, it, expect } from "vitest";
import { parseCloudflaredConfig } from "../src/core/cloudflare";
import type { LoadedFile } from "../src/core/model";

const cf = (content: string): LoadedFile => ({ path: "cloudflared/config.yml", kind: "cloudflared", content });

describe("parseCloudflaredConfig", () => {
  it("parses tunnel id and ingress rules", () => {
    const t = parseCloudflaredConfig(
      cf(`tunnel: abc-123\ncredentials-file: /etc/cloudflared/abc.json\ningress:\n  - hostname: vault.example.com\n    service: http://vaultwarden:80\n  - service: http_status:404\n`),
    );
    expect(t).toBeDefined();
    expect(t!.ingress).toHaveLength(2);
    expect(t!.ingress[0]).toMatchObject({ hostname: "vault.example.com", service: "http://vaultwarden:80" });
    expect(t!.hasAccessHint).toBe(false);
  });

  it("detects an Access hint when present", () => {
    const t = parseCloudflaredConfig(
      cf(`tunnel: abc\ningress:\n  - hostname: a.example.com\n    service: http://a:80\n# protected by cloudflare access\n`),
    );
    expect(t!.hasAccessHint).toBe(true);
  });

  it("returns undefined for a non-tunnel yaml and never throws on garbage", () => {
    expect(parseCloudflaredConfig(cf(`foo: bar\n`))).toBeUndefined();
    expect(parseCloudflaredConfig(cf(`:\n  - [\n`))).toBeUndefined();
  });
});
