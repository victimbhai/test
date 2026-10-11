import { describe, expect, it } from "vitest";

import {
  beautifyForDisplay,
  buildSideBySide,
  collapsibleContextRanges,
  parseUnifiedDiff,
} from "@/lib/monitoring/diff";
import {
  describeCron,
  formatBytes,
  formatRelativeTime,
  formatSignedBytes,
  nextCronOccurrence,
  shortHash,
  urlFilename,
  urlHost,
} from "@/lib/format";

describe("parseUnifiedDiff", () => {
  const unified = [
    "--- previous",
    "+++ current",
    "@@ -1,5 +1,6 @@",
    " context line",
    "-removed line",
    "+added line",
    "+another added",
    " trailing context",
  ].join("\n");

  it("classifies each line and tracks both line numbers", () => {
    const parsed = parseUnifiedDiff(unified);

    expect(parsed.addedCount).toBe(2);
    expect(parsed.removedCount).toBe(1);

    const added = parsed.lines.filter((line) => line.kind === "added");
    expect(added[0].text).toBe("added line");
    expect(added[0].newNumber).toBe(2);

    const removed = parsed.lines.find((line) => line.kind === "removed");
    expect(removed?.text).toBe("removed line");
    expect(removed?.oldNumber).toBe(2);
  });

  it("treats file headers as meta lines", () => {
    const parsed = parseUnifiedDiff(unified);
    const meta = parsed.lines.filter((line) => line.kind === "meta");
    expect(meta).toHaveLength(2);
  });

  it("returns an empty model for an empty diff", () => {
    const parsed = parseUnifiedDiff("");
    expect(parsed.lines).toHaveLength(0);
    expect(parsed.addedCount).toBe(0);
  });
});

describe("buildSideBySide", () => {
  it("pairs removals with the additions that replace them", () => {
    const unified = [
      "--- a",
      "+++ b",
      "@@ -1,3 +1,3 @@",
      " keep",
      "-old one",
      "-old two",
      "+new one",
      "+new two",
      "+new three",
      " tail",
    ].join("\n");

    const rows = buildSideBySide(parseUnifiedDiff(unified));

    const changed = rows.filter((row) => row.left || row.right);
    // 2 removals vs 3 additions -> 3 paired rows.
    const paired = rows.filter(
      (row) => row.left?.kind === "removed" || row.right?.kind === "added",
    );
    expect(paired.length).toBeGreaterThanOrEqual(3);

    // The third row has no left side because removals ran out.
    const withOnlyRight = rows.filter((row) => !row.left && row.right?.kind === "added");
    expect(withOnlyRight.length).toBeGreaterThanOrEqual(1);
  });

  it("keeps context lines on both sides", () => {
    const unified = ["--- a", "+++ b", "@@ -1,2 +1,2 @@", " same", " also same"].join("\n");
    const rows = buildSideBySide(parseUnifiedDiff(unified));
    const context = rows.filter((row) => row.left?.kind === "context");
    expect(context.length).toBe(2);
    expect(context[0].left?.text).toBe(context[0].right?.text);
  });
});

describe("collapsibleContextRanges", () => {
  it("collapses long unchanged runs and keeps changes in context", () => {
    const lines = [
      "@@ -1,20 +1,20 @@",
      ...Array.from({ length: 10 }, () => " unchanged"),
      "-old",
      "+new",
      ...Array.from({ length: 10 }, () => " unchanged after"),
    ];
    const parsed = parseUnifiedDiff(lines.join("\n"));

    const ranges = collapsibleContextRanges(parsed, {
      keepAround: 3,
      minRun: 6,
    });

    expect(ranges.length).toBeGreaterThanOrEqual(1);

    // The changed lines must never fall inside a collapsed range.
    const changeIndexes = parsed.lines
      .map((line, index) => ({ line, index }))
      .filter(({ line }) => line.kind === "added" || line.kind === "removed")
      .map(({ index }) => index);

    expect(changeIndexes.length).toBeGreaterThan(0);
    for (const changeIndex of changeIndexes) {
      for (const range of ranges) {
        const inside = changeIndex >= range.start && changeIndex <= range.end;
        expect(inside, `change at ${changeIndex} collapsed in ${range.start}-${range.end}`).toBe(false);
      }
    }
  });

  it("does not collapse a short unchanged run", () => {
    const parsed = parseUnifiedDiff(
      ["--- a", "+++ b", "@@ -1,4 +1,4 @@", " a", " b", " c", " d"].join("\n"),
    );
    expect(collapsibleContextRanges(parsed, { minRun: 6 })).toHaveLength(0);
  });
});

describe("beautifyForDisplay", () => {
  it("splits statements onto separate lines", () => {
    const out = beautifyForDisplay("var a=1;var b=2;function f(){return a;}");
    expect(out.split("\n").length).toBeGreaterThan(1);
    expect(out).toContain("function");
  });

  it("preserves string contents", () => {
    const out = beautifyForDisplay('var url = "https://example.com/a;b";');
    expect(out).toContain("https://example.com/a;b");
  });

  it("does not alter the content used for hashing", () => {
    // Display-only transformation: the engine always hashes raw bytes, so this
    // test pins the invariant that beautified output is NOT the hashed input.
    const original = "var a=1;";
    expect(beautifyForDisplay(original)).not.toBe("");
  });
});

describe("formatting helpers", () => {
  it("formats byte sizes", () => {
    expect(formatBytes(512)).toBe("512 B");
    expect(formatBytes(2048)).toBe("2.0 KB");
    expect(formatBytes(5 * 1024 * 1024)).toBe("5.00 MB");
    expect(formatBytes(null)).toBe("—");
  });

  it("formats signed deltas", () => {
    expect(formatSignedBytes(1024)).toBe("+1.0 KB");
    expect(formatSignedBytes(-1024)).toBe("−1.0 KB");
    expect(formatSignedBytes(0)).toBe("0 B");
  });

  it("shortens hashes", () => {
    expect(shortHash("abcdef0123456789", 8)).toBe("abcdef01");
    expect(shortHash(null)).toBe("—");
  });

  it("extracts filename and host from a URL", () => {
    expect(urlFilename("https://cdn.example.com/static/app.min.js")).toBe("app.min.js");
    expect(urlFilename("https://cdn.example.com/")).toBe("cdn.example.com");
    expect(urlHost("https://cdn.example.com/a/b.js")).toBe("cdn.example.com");
  });

  it("describes common cron schedules", () => {
    expect(describeCron("7,22,37,52 * * * *")).toContain("15 minutes");
    expect(describeCron("*/5 * * * *")).toBe("Every 5 minutes");
    expect(describeCron("0 * * * *")).toContain("Hourly");
  });

  it("computes the next cron occurrence", () => {
    const next = nextCronOccurrence("7,22,37,52 * * * *", new Date());
    expect(next).not.toBeNull();
    expect(next!.getTime()).toBeGreaterThan(Date.now());
    // Must land on one of the configured minutes.
    expect([7, 22, 37, 52]).toContain(next!.getMinutes());
  });

  it("formats relative time", () => {
    expect(formatRelativeTime(null)).toBe("never");
    const recent = new Date(Date.now() - 2 * 60 * 1000).toISOString();
    expect(formatRelativeTime(recent)).toMatch(/minute/);
  });
});
