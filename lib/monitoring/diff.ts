/**
 * Diff parsing for the Monaco viewer.
 *
 * The engine returns a unified diff plus structured hunks. This module turns
 * that into the line-by-line model Monaco needs: a flat list of lines tagged
 * as context/added/removed, with the original line numbers on each side so
 * "jump to line" stays accurate.
 */

export type DiffLineKind = "context" | "added" | "removed" | "hunk" | "meta";

export interface DiffLine {
  kind: DiffLineKind;
  text: string;
  oldNumber?: number;
  newNumber?: number;
}

export interface ParsedDiff {
  lines: DiffLine[];
  addedCount: number;
  removedCount: number;
  contextCount: number;
}

/** Parse a unified diff string into a renderable line model. */
export function parseUnifiedDiff(unified: string): ParsedDiff {
  const lines: DiffLine[] = [];
  let oldNumber = 0;
  let newNumber = 0;
  let addedCount = 0;
  let removedCount = 0;
  let contextCount = 0;
  let inHunk = false;

  for (const raw of unified.split("\n")) {
    if (raw.startsWith("---") || raw.startsWith("+++")) {
      lines.push({ kind: "meta", text: raw });
      continue;
    }

    if (raw.startsWith("@@")) {
      inHunk = true;
      lines.push({ kind: "hunk", text: raw });
      const match = /-(\d+)(?:,\d+)?\s+\+(\d+)(?:,\d+)?/.exec(raw);
      if (match) {
        oldNumber = Number(match[1]);
        newNumber = Number(match[2]);
      }
      continue;
    }

    if (!inHunk) {
      // Anything before the first hunk header is preamble.
      if (raw.trim() !== "") lines.push({ kind: "meta", text: raw });
      continue;
    }

    if (raw.startsWith("+")) {
      addedCount += 1;
      lines.push({
        kind: "added",
        text: raw.slice(1),
        newNumber: newNumber,
      });
      newNumber += 1;
      continue;
    }

    if (raw.startsWith("-")) {
      removedCount += 1;
      lines.push({
        kind: "removed",
        text: raw.slice(1),
        oldNumber: oldNumber,
      });
      oldNumber += 1;
      continue;
    }

    // Context lines are prefixed with a space; a bare empty line is also context.
    const text = raw.startsWith(" ") ? raw.slice(1) : raw;
    contextCount += 1;
    lines.push({
      kind: "context",
      text,
      oldNumber,
      newNumber,
    });
    oldNumber += 1;
    newNumber += 1;
  }

  return { lines, addedCount, removedCount, contextCount };
}

/** Build the side-by-side pairing used by the split view. */
export interface SideBySideRow {
  left: DiffLine | null;
  right: DiffLine | null;
}

export function buildSideBySide(parsed: ParsedDiff): SideBySideRow[] {
  const rows: SideBySideRow[] = [];
  let index = 0;
  const lines = parsed.lines;

  while (index < lines.length) {
    const line = lines[index];

    if (line.kind === "meta" || line.kind === "hunk") {
      rows.push({ left: line, right: line });
      index += 1;
      continue;
    }

    if (line.kind === "context") {
      rows.push({ left: line, right: line });
      index += 1;
      continue;
    }

    // Collect a run of removals followed by a run of additions.
    const removed: DiffLine[] = [];
    const added: DiffLine[] = [];

    while (index < lines.length && lines[index].kind === "removed") {
      removed.push(lines[index]);
      index += 1;
    }
    while (index < lines.length && lines[index].kind === "added") {
      added.push(lines[index]);
      index += 1;
    }

    const height = Math.max(removed.length, added.length);
    for (let i = 0; i < height; i += 1) {
      rows.push({ left: removed[i] ?? null, right: added[i] ?? null });
    }
  }

  return rows;
}

/**
 * Group context lines into collapsible blocks.
 *
 * Returns the indices of context lines that sit far from any change; the
 * viewer collapses these so a 10k-line minified bundle stays navigable.
 */
export function collapsibleContextRanges(
  parsed: ParsedDiff,
  { keepAround = 3, minRun = 6 }: { keepAround?: number; minRun?: number } = {},
): Array<{ start: number; end: number }> {
  const lines = parsed.lines;
  const nearChange = new Array<boolean>(lines.length).fill(false);

  for (let i = 0; i < lines.length; i += 1) {
    if (lines[i].kind === "added" || lines[i].kind === "removed") {
      for (
        let j = Math.max(0, i - keepAround);
        j <= Math.min(lines.length - 1, i + keepAround);
        j += 1
      ) {
        nearChange[j] = true;
      }
    }
  }

  const ranges: Array<{ start: number; end: number }> = [];
  let runStart: number | null = null;

  for (let i = 0; i < lines.length; i += 1) {
    const collapsible =
      lines[i].kind === "context" && !nearChange[i];
    if (collapsible && runStart === null) runStart = i;
    if (!collapsible && runStart !== null) {
      if (i - runStart >= minRun) ranges.push({ start: runStart, end: i - 1 });
      runStart = null;
    }
  }

  if (runStart !== null && lines.length - runStart >= minRun) {
    ranges.push({ start: runStart, end: lines.length - 1 });
  }

  return ranges;
}

/**
 * Lightweight JavaScript beautifier for display.
 *
 * The engine hashes the raw bytes; beautifying here is purely presentational
 * and never affects change detection.
 */
export function beautifyForDisplay(source: string, indent = 2): string {
  const pad = " ".repeat(indent);
  let depth = 0;
  let output = "";
  let inString: string | null = null;
  let inTemplate = false;
  let inLineComment = false;
  let inBlockComment = false;
  let inRegex = false;
  let previousMeaningful = "";

  const push = (text: string) => {
    output += text;
  };

  const newline = () => {
    output = output.replace(/[ \t]+$/, "");
    output += "\n" + pad.repeat(Math.max(0, depth));
  };

  for (let i = 0; i < source.length; i += 1) {
    const char = source[i];
    const next = source[i + 1] ?? "";

    if (inLineComment) {
      push(char);
      if (char === "\n") {
        inLineComment = false;
        push(pad.repeat(Math.max(0, depth)));
      }
      continue;
    }

    if (inBlockComment) {
      push(char);
      if (char === "*" && next === "/") {
        push("/");
        i += 1;
        inBlockComment = false;
      }
      continue;
    }

    if (inString) {
      push(char);
      if (char === "\\") {
        push(next);
        i += 1;
        continue;
      }
      if (char === inString) inString = null;
      continue;
    }

    if (inTemplate) {
      push(char);
      if (char === "\\") {
        push(next);
        i += 1;
        continue;
      }
      if (char === "`") inTemplate = false;
      continue;
    }

    if (inRegex) {
      push(char);
      if (char === "\\") {
        push(next);
        i += 1;
        continue;
      }
      if (char === "[") {
        // Skip character class contents.
        i += 1;
        while (i < source.length && source[i] !== "]") {
          push(source[i]);
          i += 1;
        }
        if (i < source.length) push(source[i]);
        continue;
      }
      if (char === "/") inRegex = false;
      continue;
    }

    if (char === "/" && next === "/") {
      inLineComment = true;
      push("//");
      i += 1;
      continue;
    }

    if (char === "/" && next === "*") {
      inBlockComment = true;
      push("/*");
      i += 1;
      continue;
    }

    if (char === '"' || char === "'") {
      inString = char;
      push(char);
      continue;
    }

    if (char === "`") {
      inTemplate = true;
      push(char);
      continue;
    }

    // Regex literal detection: a '/' that follows an operator or keyword.
    if (char === "/" && !/[\w$)\]]/.test(previousMeaningful)) {
      inRegex = true;
      push(char);
      previousMeaningful = char;
      continue;
    }

    if (char === "{") {
      depth += 1;
      push(char);
      newline();
      previousMeaningful = char;
      continue;
    }

    if (char === "}") {
      depth = Math.max(0, depth - 1);
      newline();
      push(char);
      previousMeaningful = char;
      continue;
    }

    if (char === ";") {
      push(char);
      if (next !== ")") newline();
      previousMeaningful = char;
      continue;
    }

    if (char === "\n") {
      newline();
      previousMeaningful = "";
      continue;
    }

    if (char === " " || char === "\t") {
      if (!output.endsWith(" ") && !output.endsWith("\n") && !output.endsWith(pad)) {
        push(" ");
      }
      continue;
    }

    push(char);
    previousMeaningful = char;
  }

  return output
    .split("\n")
    .map((line) => line.replace(/\s+$/, ""))
    .join("\n")
    .replace(/\n{3,}/g, "\n\n")
    .trim();
}
