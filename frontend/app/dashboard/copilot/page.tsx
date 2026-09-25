"use client";

import { useEffect, useRef, useState, type ChangeEvent, type ReactNode } from "react";
import { useRouter } from "next/navigation";
import { Paperclip, X } from "lucide-react";
import { apiFetch, copilotSocketUrl, clearToken } from "@/lib/api";

interface Message {
  role: "user" | "assistant";
  text: string;
  streaming?: boolean;
  attachmentName?: string;
}

interface CopilotDocument {
  filename: string;
  text: string;
  character_count: number;
  truncated: boolean;
}

function renderInlineMarkdown(text: string, keyPrefix: string): ReactNode[] {
  const tokenPattern = /(\*\*.+?\*\*|__.+?__|`[^`]+`|\*[^*]+\*|_[^_]+_)/g;
  return text.split(tokenPattern).filter(Boolean).map((part, index) => {
    const key = `${keyPrefix}-${index}`;
    if ((part.startsWith("**") && part.endsWith("**")) || (part.startsWith("__") && part.endsWith("__"))) {
      return <strong key={key} className="font-semibold text-text-primary">{part.slice(2, -2)}</strong>;
    }
    if (part.startsWith("`")) {
      return <code key={key} className="rounded bg-secondary px-1 py-0.5 font-mono text-[0.9em]">{part.slice(1, -1)}</code>;
    }
    if ((part.startsWith("*") && part.endsWith("*")) || (part.startsWith("_") && part.endsWith("_"))) {
      return <em key={key}>{part.slice(1, -1)}</em>;
    }
    return part;
  });
}

function MarkdownMessage({ text }: { text: string }) {
  const lines = text.replace(/\r/g, "").split("\n");
  const blocks: ReactNode[] = [];
  let index = 0;

  while (index < lines.length) {
    const line = lines[index].trim();
    if (!line) {
      index += 1;
      continue;
    }

    const heading = line.match(/^(#{1,3})\s+(.+)$/);
    if (heading) {
      const content = renderInlineMarkdown(heading[2], `h-${index}`);
      const className = heading[1].length === 1
        ? "mb-2 mt-4 text-base font-semibold text-text-primary first:mt-0"
        : "mb-1 mt-3 font-semibold text-text-primary first:mt-0";
      blocks.push(heading[1].length === 1
        ? <h3 key={`block-${index}`} className={className}>{content}</h3>
        : <h4 key={`block-${index}`} className={className}>{content}</h4>);
      index += 1;
      continue;
    }

    if (line.startsWith("```")) {
      const codeLines: string[] = [];
      index += 1;
      while (index < lines.length && !lines[index].trim().startsWith("```")) {
        codeLines.push(lines[index]);
        index += 1;
      }
      index += 1;
      blocks.push(<pre key={`block-${index}`} className="my-2 overflow-x-auto rounded-md bg-secondary p-3 font-mono text-xs"><code>{codeLines.join("\n")}</code></pre>);
      continue;
    }

    const isTable = line.startsWith("|") && index + 1 < lines.length && /^\|?\s*:?-{3,}/.test(lines[index + 1].trim());
    if (isTable) {
      const parseCells = (row: string) => row.trim().replace(/^\|/, "").replace(/\|$/, "").split("|").map((cell) => cell.trim());
      const header = parseCells(line);
      index += 2;
      const rows: string[][] = [];
      while (index < lines.length && lines[index].trim().startsWith("|")) {
        rows.push(parseCells(lines[index]));
        index += 1;
      }
      blocks.push(
        <div key={`block-${index}`} className="my-3 overflow-x-auto">
          <table className="w-full border-collapse text-left text-xs">
            <thead><tr>{header.map((cell, cellIndex) => <th key={cellIndex} className="border border-border bg-secondary px-2 py-1.5 font-semibold">{renderInlineMarkdown(cell, `th-${index}-${cellIndex}`)}</th>)}</tr></thead>
            <tbody>{rows.map((row, rowIndex) => <tr key={rowIndex}>{header.map((_, cellIndex) => <td key={cellIndex} className="border border-border px-2 py-1.5 align-top">{renderInlineMarkdown(row[cellIndex] || "", `td-${index}-${rowIndex}-${cellIndex}`)}</td>)}</tr>)}</tbody>
          </table>
        </div>
      );
      continue;
    }

    const unordered = line.match(/^[-*+]\s+(.+)$/);
    const ordered = line.match(/^\d+[.)]\s+(.+)$/);
    if (unordered || ordered) {
      const items: string[] = [];
      const pattern = ordered ? /^\d+[.)]\s+(.+)$/ : /^[-*+]\s+(.+)$/;
      while (index < lines.length) {
        const item = lines[index].trim().match(pattern);
        if (!item) break;
        items.push(item[1]);
        index += 1;
      }
      const List = ordered ? "ol" : "ul";
      blocks.push(
        <List key={`block-${index}`} className={`my-2 space-y-1 pl-5 ${ordered ? "list-decimal" : "list-disc"}`}>
          {items.map((item, itemIndex) => <li key={itemIndex}>{renderInlineMarkdown(item, `li-${index}-${itemIndex}`)}</li>)}
        </List>
      );
      continue;
    }

    if (line.startsWith("> ")) {
      blocks.push(<blockquote key={`block-${index}`} className="my-2 border-l-2 border-gold pl-3 text-text-secondary">{renderInlineMarkdown(line.slice(2), `quote-${index}`)}</blockquote>);
      index += 1;
      continue;
    }

    const paragraph: string[] = [];
    while (index < lines.length && lines[index].trim() && !/^(#{1,3}\s|[-*+]\s|\d+[.)]\s|>\s|\|)/.test(lines[index].trim())) {
      paragraph.push(lines[index].trim());
      index += 1;
    }
    if (paragraph.length === 0) {
      paragraph.push(lines[index].trim());
      index += 1;
    }
    blocks.push(<p key={`block-${index}`} className="my-2 leading-6 first:mt-0 last:mb-0">{renderInlineMarkdown(paragraph.join(" "), `p-${index}`)}</p>);
  }

  return <div className="min-w-0 break-words">{blocks}</div>;
}

export default function CopilotPage() {
  const router = useRouter();
  const [tenantId, setTenantId] = useState<string | null>(null);
  const [messages, setMessages] = useState<Message[]>([]);
  const [input, setInput] = useState("");
  const [connected, setConnected] = useState(false);
  const [llmStatus, setLlmStatus] = useState<{ provider: string | null; mode: string; detail?: string | null } | null>(null);
  const [summary, setSummary] = useState<import("@/lib/types").AnalyticsSummary | null>(null);
  const [attachment, setAttachment] = useState<CopilotDocument | null>(null);
  const [uploading, setUploading] = useState(false);
  const [attachmentError, setAttachmentError] = useState("");
  const wsRef = useRef<WebSocket | null>(null);
  const conversationRef = useRef<HTMLDivElement | null>(null);
  const fileInputRef = useRef<HTMLInputElement | null>(null);

  useEffect(() => {
    const conversation = conversationRef.current;
    if (conversation) conversation.scrollTop = conversation.scrollHeight;
  }, [messages]);

  useEffect(() => {
    const selectedTenantId = new URLSearchParams(window.location.search).get("tenant_id");
    setTenantId(selectedTenantId);
    const scope = selectedTenantId ? `?tenant_id=${encodeURIComponent(selectedTenantId)}` : "";
    apiFetch<import("@/lib/types").AnalyticsSummary>(`/analytics/summary${scope}`).then(setSummary).catch(() => {});
    apiFetch<{ provider: string | null; mode: string; detail?: string | null }>('/copilot/status').then(setLlmStatus).catch(() => {});
    const ws = new WebSocket(copilotSocketUrl(selectedTenantId));
    ws.onopen = () => setConnected(true);
    ws.onclose = (event) => {
      setConnected(false);
      if (event.code === 4401) {
        clearToken();
        router.push("/login");
      }
    };
    ws.onmessage = (event) => {
      if (event.data === "[[END]]") {
        setMessages((prev) => {
          const last = prev[prev.length - 1];
          if (last?.role !== "assistant" || !last.streaming) return prev;
          const copy = [...prev];
          copy[copy.length - 1] = { ...last, streaming: false };
          return copy;
        });
        return;
      }
      setMessages((prev) => {
        const last = prev[prev.length - 1];
        if (last?.role === "assistant" && last.streaming) {
          const copy = [...prev];
          copy[copy.length - 1] = { ...last, text: last.text + event.data };
          return copy;
        }
        return [...prev, { role: "assistant", text: event.data, streaming: true } as Message];
      });
    };
    wsRef.current = ws;
    return () => ws.close();
  }, []);

  async function attachDocument(event: ChangeEvent<HTMLInputElement>) {
    const file = event.target.files?.[0];
    event.target.value = "";
    if (!file) return;
    setUploading(true);
    setAttachmentError("");
    const form = new FormData();
    form.append("file", file);
    try {
      const extracted = await apiFetch<CopilotDocument>("/copilot/documents/extract", {
        method: "POST",
        body: form,
      });
      setAttachment(extracted);
    } catch (error) {
      setAttachmentError(error instanceof Error ? error.message : "Could not read this document.");
    } finally {
      setUploading(false);
    }
  }

  function send() {
    const question = input.trim();
    if (!question || uploading || !wsRef.current || wsRef.current.readyState !== WebSocket.OPEN) return;
    setMessages((prev) => [...prev, {
      role: "user",
      text: question,
      attachmentName: attachment?.filename,
    }]);
    wsRef.current.send(JSON.stringify({
      question,
      document: attachment ? { filename: attachment.filename, text: attachment.text } : null,
    }));
    setInput("");
  }

  return (
    <div className="max-w-2xl flex flex-col h-[80vh]">
      <div className="flex items-center justify-between mb-4">
        <div>
          <h1 className="text-2xl font-semibold">Copilot</h1>
          <p className="text-xs text-text-secondary">
            {tenantId ? "Tenant-scoped context" : "Current tenant context"} · grounded in the top 15 incidents by risk, out of {summary?.total_incidents ?? "—"} loaded.
          </p>
        </div>
        <div className="flex items-center gap-3">
          <span className={`text-xs ${connected ? "text-success" : "text-text-secondary"}`}>
            {connected ? 'connected' : 'connecting…'}
          </span>
          <span className={`text-xs ${llmStatus?.provider ? 'text-success' : 'text-warning'}`}>
            {llmStatus?.provider ? `LLM: ${llmStatus.provider}` : `LLM: ${llmStatus?.detail || 'unavailable'}`}
          </span>
        </div>
      </div>

      <div ref={conversationRef} className="card mb-4 flex-1 space-y-3 overflow-y-auto">
        {messages.length === 0 && (
          <p className="text-text-secondary text-sm">
            Ask about your incident data — e.g. &ldquo;which users have the most high-risk
            transfers?&rdquo;
          </p>
        )}
        {messages.map((m, i) => (
          <div key={i} className={`flex ${m.role === "user" ? "justify-end" : "justify-start"}`}>
            <div
              className={`max-w-[92%] rounded-lg px-4 py-3 text-sm ${
                m.role === "user" ? "bg-gold/15 text-gold" : "border border-border bg-primary text-text-primary"
              }`}
            >
              {m.role === "assistant" ? <MarkdownMessage text={m.text} /> : m.text}
              {m.role === "user" && m.attachmentName && (
                <div className="mt-2 flex items-center gap-1 text-xs opacity-80">
                  <Paperclip size={13} /> {m.attachmentName}
                </div>
              )}
              {m.streaming && <span className="ml-1 inline-block h-3 w-1 animate-pulse bg-gold align-middle" aria-label="Copilot is responding" />}
            </div>
          </div>
        ))}
      </div>

      {attachment && (
        <div className="mb-2 flex items-center justify-between rounded-md border border-border bg-secondary px-3 py-2 text-xs">
          <span className="flex min-w-0 items-center gap-2 truncate">
            <Paperclip size={14} className="shrink-0 text-gold" />
            <span className="truncate">{attachment.filename}</span>
            <span className="shrink-0 text-text-secondary">
              {attachment.truncated ? "First 60,000 characters attached" : `${attachment.character_count.toLocaleString()} characters`}
            </span>
          </span>
          <button type="button" onClick={() => setAttachment(null)} className="ml-2 rounded p-1 text-text-secondary hover:text-text-primary" aria-label="Remove attachment">
            <X size={15} />
          </button>
        </div>
      )}
      {attachmentError && <p className="mb-2 text-xs text-danger">{attachmentError}</p>}
      <div className="flex gap-2">
        <input
          ref={fileInputRef}
          type="file"
          accept=".pdf,.docx,.txt,.md,.csv"
          className="hidden"
          onChange={attachDocument}
        />
        <button
          type="button"
          onClick={() => fileInputRef.current?.click()}
          disabled={uploading}
          className="btn-secondary px-3"
          title="Attach a PDF, DOCX, TXT, Markdown, or CSV document"
          aria-label="Attach a document"
        >
          {uploading ? "Reading…" : <Paperclip size={18} />}
        </button>
        <input
          className="input flex-1"
          value={input}
          onChange={(e) => setInput(e.target.value)}
          onKeyDown={(e) => e.key === "Enter" && send()}
          placeholder="Ask the copilot…"
        />
        <button onClick={send} disabled={!connected || uploading} className="btn-primary disabled:cursor-not-allowed disabled:opacity-60">
          Send
        </button>
      </div>
    </div>
  );
}
