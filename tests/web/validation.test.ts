import { describe, expect, it } from "vitest";

import {
  isBlockedHost,
  isHostInScope,
  looksLikeJavaScript,
  parseMonitoringUrl,
  parseUrlList,
} from "@/lib/validation/schemas";

/**
 * URL validation and SSRF protection.
 *
 * These mirror monitor/jsmon/ssrf.py: the browser rejects early for good UX,
 * and the Python engine re-validates before any fetch.
 */
describe("parseMonitoringUrl", () => {
  it("accepts public http(s) URLs", () => {
    expect(parseMonitoringUrl("https://example.com/static/main.js").host).toBe(
      "example.com",
    );
    expect(parseMonitoringUrl("http://cdn.example.com/a.js?v=2").scheme).toBe("http");
    expect(parseMonitoringUrl("https://sub.example.com/x.mjs").host).toBe(
      "sub.example.com",
    );
  });

  it("rejects non-http schemes", () => {
    for (const url of [
      "file:///etc/passwd",
      "ftp://example.com/a.js",
      "javascript:alert(1)",
      "data:text/javascript,alert(1)",
      "gopher://example.com/",
    ]) {
      expect(() => parseMonitoringUrl(url), url).toThrow(/only http and https/i);
    }
  });

  it("rejects loopback and private destinations", () => {
    for (const url of [
      "http://localhost/admin.js",
      "http://127.0.0.1/config.js",
      "http://2130706433/app.js",
      "http://[::1]/app.js",
      "http://10.0.0.5/app.js",
      "http://192.168.1.1/app.js",
      "http://172.16.0.1/app.js",
      "http://169.254.169.254/latest/meta-data/",
      "http://metadata.google.internal/computeMetadata/v1/",
    ]) {
      expect(() => parseMonitoringUrl(url), url).toThrow();
    }
  });

  it("rejects credentials embedded in the URL", () => {
    expect(() => parseMonitoringUrl("https://user:pass@example.com/a.js")).toThrow(
      /credentials/i,
    );
  });

  it("rejects empty, oversized and malformed input", () => {
    expect(() => parseMonitoringUrl("")).toThrow();
    expect(() => parseMonitoringUrl("   ")).toThrow();
    expect(() => parseMonitoringUrl("not a url")).toThrow();
    expect(() => parseMonitoringUrl(`https://example.com/${"a".repeat(2100)}`)).toThrow();
  });
});

describe("isBlockedHost", () => {
  it("blocks internal names", () => {
    expect(isBlockedHost("localhost")).toBe(true);
    expect(isBlockedHost("metadata.google.internal")).toBe(true);
    expect(isBlockedHost("instance-data")).toBe(true);
  });

  it("blocks private ranges", () => {
    expect(isBlockedHost("10.1.2.3")).toBe(true);
    expect(isBlockedHost("172.20.0.1")).toBe(true);
    expect(isBlockedHost("192.168.0.10")).toBe(true);
    expect(isBlockedHost("169.254.169.254")).toBe(true);
    expect(isBlockedHost("0.0.0.0")).toBe(true);
  });

  it("blocks IPv4-mapped IPv6 loopback", () => {
    expect(isBlockedHost("::ffff:127.0.0.1")).toBe(true);
  });

  it("allows public addresses", () => {
    expect(isBlockedHost("example.com")).toBe(false);
    expect(isBlockedHost("93.184.216.34")).toBe(false);
    expect(isBlockedHost("8.8.8.8")).toBe(false);
  });
});

describe("isHostInScope", () => {
  it("matches the host and its subdomains", () => {
    expect(isHostInScope("example.com", ["example.com"])).toBe(true);
    expect(isHostInScope("cdn.example.com", ["example.com"])).toBe(true);
    expect(isHostInScope("a.b.example.com", ["example.com"])).toBe(true);
  });

  it("accepts a leading-dot or wildcard form", () => {
    expect(isHostInScope("cdn.example.com", [".example.com"])).toBe(true);
    expect(isHostInScope("cdn.example.com", ["*.example.com"])).toBe(true);
  });

  it("rejects lookalike hosts", () => {
    expect(isHostInScope("notexample.com", ["example.com"])).toBe(false);
    expect(isHostInScope("example.com.evil.net", ["example.com"])).toBe(false);
  });

  it("treats an empty allowlist as unrestricted", () => {
    expect(isHostInScope("anything.test", [])).toBe(true);
  });

  it("supports multiple entries", () => {
    expect(isHostInScope("cdn.other.net", ["example.com", "other.net"])).toBe(true);
  });
});

describe("looksLikeJavaScript", () => {
  it("recognises script extensions", () => {
    expect(looksLikeJavaScript("https://example.com/main.js")).toBe(true);
    expect(looksLikeJavaScript("https://example.com/mod.mjs")).toBe(true);
    expect(looksLikeJavaScript("https://example.com/x.cjs")).toBe(true);
  });

  it("recognises common bundle paths", () => {
    expect(looksLikeJavaScript("https://example.com/_next/static/chunk")).toBe(true);
    expect(looksLikeJavaScript("https://example.com/build/output")).toBe(true);
  });

  it("rejects non-script assets", () => {
    expect(looksLikeJavaScript("https://example.com/style.css")).toBe(false);
    expect(looksLikeJavaScript("https://example.com/logo.png")).toBe(false);
    expect(looksLikeJavaScript("https://example.com/fonts/a.woff2")).toBe(false);
  });
});

describe("parseUrlList", () => {
  it("parses, normalises and deduplicates a pasted list", () => {
    const { valid, invalid, duplicates } = parseUrlList(`
      # a comment
      https://a.example.com/one.js

      https://b.example.com/two.js
      https://a.example.com/one.js
      garbage
      http://localhost/x.js
    `);

    expect(valid).toEqual([
      "https://a.example.com/one.js",
      "https://b.example.com/two.js",
    ]);
    expect(duplicates).toBe(1);
    expect(invalid).toHaveLength(2);
  });

  it("reports the reason for each rejected line", () => {
    const { invalid } = parseUrlList("http://127.0.0.1/a.js");
    expect(invalid[0].reason).toMatch(/internal|loopback|private/i);
  });

  it("handles an empty input", () => {
    const { valid, invalid } = parseUrlList("");
    expect(valid).toEqual([]);
    expect(invalid).toEqual([]);
  });

  it("treats URLs differing only by case as duplicates", () => {
    const { valid, duplicates } = parseUrlList(
      "https://example.com/A.js\nhttps://EXAMPLE.com/A.js",
    );
    expect(valid).toHaveLength(1);
    expect(duplicates).toBe(1);
  });
});
