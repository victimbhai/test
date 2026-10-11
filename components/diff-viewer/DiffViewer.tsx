"use client";

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import type { editor } from "monaco-editor";
import { DiffEditor } from "@monaco-editor/react";
import {
  AlertTriangle,
  ChevronDown,
  ChevronRight,
  Copy,
  Download,
  Search,
  ShieldAlert,
  X,
} from "lucide-react";

import { cn } from "@/lib/utils";
import { beautifyForDisplay } from "@/lib/monitoring/diff";
import type { DiffPayload, ReviewIndicator } from "@/lib/supabase/types";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";

/**
 * Monaco-based JavaScript diff viewer.
 *
 * Capabilities:
 *   - side-by-side and unified layouts
 *   - syntax highlighting with added/removed line emphasis
 *   - in-editor search (Monaco's own find widget)
 *   - collapsed unchanged regions for large bundles
 *   - beautified view (display only — hashing uses the original bytes)
 *   - security review indicators with jump-to-line
 *   - copy and download
 *
 * SECURITY: snapshot text is rendered strictly as code inside Monaco. It is
 * never injected as HTML, so downloaded JavaScript cannot execute in the
 * dashboard's origin.
 */

export interface DiffViewerProps {
  diff: DiffPayload;
  oldSource?: string;
  newSource?: string;
  filename?: string;
  className?: string;
  readOnly?: boolean;
}

type Layout = "split" | "unified";
type View = "original" | "beautified";

const SEVERITY_ORDER: Record<string, number> = { high: 0, medium: 1, low: 2 };

export function DiffViewer({
  diff,
  oldSource,
  newSource,
  filename = "script.js",
  className,
  readOnly = true,
}: DiffViewerProps) {
  const [layout, setLayout] = useState<Layout>("split");
  const [view, setView] = useState<View>("original");
  const [beautified, setBeautified] = useState(false);
  const [showIndicators, setShowIndicators] = useState(true);
  const editorRef = useRef<editor.IStandaloneDiffEditor | null>(null);

  const left = oldSource ?? "";
  const right = newSource ?? "";

  const leftText = useMemo(
    () => (view === "beautified" ? beautifyForDisplay(left) : left),
    [left, view],
  );
  const rightText = useMemo(
    () => (view === "beautified" ? beautifyForDisplay(right) : right),
    [right, view],
  );

  const indicators = useMemo(
    () =>
      [...(diff.indicators ?? [])].sort(
        (a, b) =>
          (SEVERITY_ORDER[a.severity] ?? 9) - (SEVERITY_ORDER[b.severity] ?? 9),
      ),
    [diff.indicators],
  );

  const severityTone = (severity: string) =>
    severity === "high" ? "bad" : severity === "medium" ? "warn" : "neutral";

  const handleMount = useCallback(
    (editor: editor.IStandaloneDiffEditor) => {
      editorRef.current = editor;
    },
    [],
  );

  /** Jump to a line in the modified editor. */
  const jumpTo = useCallback((lineNumber: number) => {
    const instance = editorRef.current;
    if (!instance) return;
    const modified = instance.getModifiedEditor();
    modified.revealLineInCenter(lineNumber);
    modified.setPosition({ lineNumber, column: 1 });
    modified.focus();
  }, []);

  const copyUnified = useCallback(async () => {
    try {
      await navigator.clipboard.writeText(diff.unified);
    } catch {
      // Clipboard permission denied: fall back to a download.
      downloadText("changes.diff", diff.unified);
    }
  }, [diff.unified]);

  const downloadUnified = useCallback(() => {
    downloadText(`${filename}.diff`, diff.unified);
  }, [diff.unified, filename]);

  const downloadNew = useCallback(() => {
    downloadText(filename, right);
  }, [right, filename]);

  const openSearch = useCallback(() => {
    const instance = editorRef.current;
    if (!instance) return;
    instance.getModifiedEditor().getAction("actions.find")?.run();
  }, []);

  const editorOptions: editor.IDiffEditorConstructionOptions = {
    readOnly,
    renderSideBySide: layout === "split",
    originalEditable: false,
    minimap: { enabled: false },
    scrollBeyondLastLine: false,
    fontSize: 12.5,
    lineHeight: 19,
    fontFamily:
      "var(--font-geist-mono), ui-monospace, SFMono-Regular, Menlo, monospace",
    fontLigatures: true,
    wordWrap: "on",
    renderWhitespace: "selection",
    smoothScrolling: true,
    automaticLayout: true,
    scrollbar: {
      verticalScrollbarSize: 10,
      horizontalScrollbarSize: 10,
    },
    hideUnchangedRegions: {
      enabled: false,
    },
    diffAlgorithm: "advanced",
    renderOverviewRuler: true,
    overviewRulerBorder: false,
    padding: { top: 12, bottom: 12 },
    // Untrusted content: disable every feature that could fetch or execute.
    links: false,
    contextmenu: false,
    quickSuggestions: false,
    parameterHints: { enabled: false },
    hover: { enabled: "off", sticky: false, above: false },
    occurrencesHighlight: "off",
    selectionHighlight: false,
    matchBrackets: "never",
    stickyTabStops: false,
  };

  return (
    <div className={cn("flex flex-col gap-3", className)}>
      {/* Toolbar */}
      <div className="flex flex-wrap items-center gap-2 rounded-lg border border-[var(--border)] bg-[var(--surface)] p-2">
        <div className="flex items-center gap-1 rounded-md bg-[var(--surface-raised)] p-0.5">
          {(["split", "unified"] as Layout[]).map((mode) => (
            <button
              key={mode}
              type="button"
              onClick={() => setLayout(mode)}
              className={cn(
                "rounded px-2.5 py-1 text-xs font-medium capitalize transition-colors",
                layout === mode
                  ? "bg-accent-500/20 text-accent-300"
                  : "text-[var(--muted)] hover:text-[var(--foreground)]",
              )}
            >
              {mode === "split" ? "Side by side" : "Unified"}
            </button>
          ))}
        </div>

        <div className="flex items-center gap-1 rounded-md bg-[var(--surface-raised)] p-0.5">
          {(["original", "beautified"] as View[]).map((mode) => (
            <button
              key={mode}
              type="button"
              onClick={() => setView(mode)}
              className={cn(
                "rounded px-2.5 py-1 text-xs font-medium capitalize transition-colors",
                view === mode
                  ? "bg-accent-500/20 text-accent-300"
                  : "text-[var(--muted)] hover:text-[var(--foreground)]",
              )}
              title={
                mode === "beautified"
                  ? "Display only — hashing always uses the original bytes"
                  : undefined
              }
            >
              {mode}
            </button>
          ))}
        </div>

        <div className="ml-auto flex items-center gap-1.5">
          <Button
            variant="ghost"
            size="sm"
            onClick={openSearch}
            title="Search within code"
          >
            <Search className="h-3.5 w-3.5" />
            Search
          </Button>
          <Button variant="ghost" size="sm" onClick={copyUnified} title="Copy changes">
            <Copy className="h-3.5 w-3.5" />
            Copy
          </Button>
          <Button
            variant="ghost"
            size="sm"
            onClick={downloadUnified}
            title="Download the diff"
          >
            <Download className="h-3.5 w-3.5" />
            Diff
          </Button>
          <Button
            variant="ghost"
            size="sm"
            onClick={downloadNew}
            title="Download the current snapshot"
          >
            <Download className="h-3.5 w-3.5" />
            File
          </Button>
        </div>
      </div>

      {/* Indicator summary */}
      {indicators.length > 0 && (
        <div className="flex items-center gap-2">
          <button
            type="button"
            onClick={() => setShowIndicators((v) => !v)}
            className="flex items-center gap-1.5 text-xs font-medium text-[var(--muted)] hover:text-[var(--foreground)]"
          >
            {showIndicators ? (
              <ChevronDown className="h-3.5 w-3.5" />
            ) : (
              <ChevronRight className="h-3.5 w-3.5" />
            )}
            <ShieldAlert className="h-3.5 w-3.5 text-warn-400" />
            {indicators.length} review indicator
            {indicators.length === 1 ? "" : "s"}
          </button>
          <span className="text-xs text-[var(--muted)]">
            (review prompts, not confirmed vulnerabilities)
          </span>
        </div>
      )}

      {showIndicators && indicators.length > 0 && (
        <div className="max-h-52 space-y-1.5 overflow-y-auto rounded-lg border border-[var(--border)] bg-[var(--surface)] p-2">
          {indicators.map((indicator, index) => (
            <IndicatorRow
              key={`${indicator.label}-${indicator.line_number}-${index}`}
              indicator={indicator}
              onJump={() => jumpTo(indicator.line_number)}
              tone={severityTone(indicator.severity)}
            />
          ))}
        </div>
      )}

      {/* Editor */}
      <div className="monaco-host border border-[var(--border)] bg-[var(--surface)]">
        <DiffEditor
          height="560px"
          language="javascript"
          original={leftText}
          modified={rightText}
          theme="vs-dark"
          onMount={handleMount}
          options={editorOptions}
          loading={
            <div className="flex h-full items-center justify-center text-sm text-[var(--muted)]">
              Loading diff viewer…
            </div>
          }
        />
      </div>

      {/* Metadata footer */}
      <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-[var(--muted)]">
        <span>
          +{diff.added_lines} added / −{diff.removed_lines} removed
        </span>
        <span>
          {diff.old_lines} → {diff.new_lines} lines
        </span>
        {diff.truncated && (
          <Badge variant="warn">
            <AlertTriangle className="h-3 w-3" />
            Diff truncated
          </Badge>
        )}
        <span className="ml-auto">{filename}</span>
      </div>
    </div>
  );
}

function IndicatorRow({
  indicator,
  onJump,
  tone,
}: {
  indicator: ReviewIndicator;
  onJump: () => void;
  tone: "bad" | "warn" | "neutral";
}) {
  const [expanded, setExpanded] = useState(false);

  return (
    <div className="rounded-md border border-[var(--border)] bg-[var(--surface-raised)]">
      <div className="flex items-center gap-2 px-2 py-1.5">
        <button
          type="button"
          onClick={() => setExpanded((v) => !v)}
          className="flex min-w-0 flex-1 items-center gap-2 text-left"
        >
          {expanded ? (
            <X className="h-3 w-3 shrink-0 text-[var(--muted)]" />
          ) : (
            <ChevronRight className="h-3 w-3 shrink-0 text-[var(--muted)]" />
          )}
          <Badge variant={tone}>{indicator.severity}</Badge>
          <span className="truncate text-xs font-medium text-[var(--foreground)]">
            {indicator.label}
          </span>
          <span className="shrink-0 text-xs text-[var(--muted)]">
            {indicator.category}
          </span>
        </button>
        <button
          type="button"
          onClick={onJump}
          className="shrink-0 rounded px-1.5 py-0.5 font-mono text-xs text-accent-400 hover:bg-accent-500/10"
          title="Jump to this line"
        >
          L{indicator.line_number}
        </button>
      </div>
      {expanded && (
        <div className="border-t border-[var(--border)] px-2 py-1.5">
          <code className="block break-all font-mono text-xs text-[var(--muted)]">
            {indicator.match}
          </code>
          {indicator.context && (
            <pre className="mt-1 max-h-32 overflow-auto whitespace-pre-wrap break-all font-mono text-[11px] text-[var(--foreground)]">
              {indicator.context}
            </pre>
          )}
        </div>
      )}
    </div>
  );
}

function downloadText(filename: string, content: string) {
  const blob = new Blob([content], { type: "text/plain;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = filename;
  document.body.appendChild(anchor);
  anchor.click();
  document.body.removeChild(anchor);
  URL.revokeObjectURL(url);
}

/** Lazy wrapper so Monaco's ~3MB payload is not in the initial bundle. */
export { DiffViewer as default };
