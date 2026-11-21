"use client";

import { useEffect, useRef, useState } from "react";
import type { FormEvent, KeyboardEvent } from "react";
import { Bot, Send, ShieldCheck, X, Sparkles, LoaderCircle, Trash2 } from "lucide-react";

type Message = { role: "user" | "assistant"; content: string; id: string };

const starters = [
  "كيف أحمي شبكتي المنزلية؟",
  "اشرح لي ثغرات CVE وكيف أقيّم خطورتها.",
  "كيف أبدأ مختبر اختبار اختراق قانوني؟"
];

export default function CyberAssistant() {
  const [open, setOpen] = useState(false);
  const [ready, setReady] = useState<boolean | null>(null);
  const [messages, setMessages] = useState<Message[]>([]);
  const [input, setInput] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const scrollRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    fetch("/api/assistant/chat", { cache: "no-store" })
      .then((r) => r.json())
      .then((data) => setReady(Boolean(data.configured)))
      .catch(() => setReady(false));
  }, []);

  useEffect(() => {
    scrollRef.current?.scrollTo({ top: scrollRef.current.scrollHeight, behavior: "smooth" });
  }, [messages, busy, open]);

  async function sendMessage(text = input) {
    const content = text.trim();
    if (!content || busy) return;
    const next: Message[] = [...messages, { role: "user", content, id: crypto.randomUUID() }];
    setMessages(next);
    setInput("");
    setError("");
    setBusy(true);
    try {
      const response = await fetch("/api/assistant/chat", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ messages: next.slice(-11).map(({ role, content }) => ({ role, content })) })
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || "تعذر إرسال الرسالة.");
      setMessages((current) => [...current, { role: "assistant", content: data.answer, id: crypto.randomUUID() }]);
    } catch (err) {
      // Remove the failed user turn so it is not silently resent next time.
      setMessages((current) => current.filter((message) => message.id !== next[next.length - 1].id));
      setError(err instanceof Error ? err.message : "حدث خطأ غير متوقع.");
    } finally {
      setBusy(false);
    }
  }

  function onSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    void sendMessage();
  }

  function onKeyDown(event: KeyboardEvent<HTMLTextAreaElement>) {
    if (event.key === "Enter" && !event.shiftKey) {
      event.preventDefault();
      void sendMessage();
    }
  }

  return (
    <>
      {open && (
        <section className="cyber-chat" aria-label="محادثة المساعد الأمني">
          <header className="cyber-chat-head">
            <div className="cyber-chat-brand">
              <div className="cyber-chat-avatar"><ShieldCheck size={21} /></div>
              <div><strong>Cyber AI Assistant</strong><small><i /> مساعد الأمن السيبراني</small></div>
            </div>
            <div className="cyber-chat-actions">
              <button type="button" title="مسح المحادثة" aria-label="مسح المحادثة" disabled={busy} onClick={() => { setMessages([]); setError(""); }}><Trash2 size={16} /></button>
              <button type="button" title="إغلاق" aria-label="إغلاق المحادثة" onClick={() => setOpen(false)}><X size={19} /></button>
            </div>
          </header>
          <div className="cyber-chat-status">
            <span className={ready ? "cyber-status-dot ready" : "cyber-status-dot"} />
            {ready === null ? "جارٍ التحقق من الاتصال..." : ready ? "الإعدادات موجودة؛ الاتصال لم يُختبر بعد" : "بانتظار إعداد محرك الذكاء الاصطناعي"}
          </div>
          <div className="cyber-chat-messages" ref={scrollRef} aria-live="polite" aria-relevant="additions text">
            {messages.length === 0 ? (
              <div className="cyber-chat-welcome">
                <div className="cyber-welcome-icon"><Sparkles size={22} /></div>
                <h3>مرحباً بك في Cyber AI</h3>
                <p>اسأل عن الأمن السيبراني، حماية الأنظمة، تحليل الثغرات، أو التعلّم داخل مختبر مصرح به.</p>
                <div className="cyber-starters">{starters.map((item) => <button key={item} type="button" onClick={() => void sendMessage(item)}>{item}</button>)}</div>
              </div>
            ) : messages.map((message) => (
              <div key={message.id} className={`cyber-message ${message.role}`}>
                {message.role === "assistant" && <span className="cyber-message-icon"><Bot size={15} /></span>}
                <div className="cyber-message-bubble">{message.content}</div>
              </div>
            ))}
            {busy && <div className="cyber-thinking"><LoaderCircle size={15} className="cyber-spin" /> يكتب المساعد إجابة...</div>}
            {error && <div className="cyber-chat-error">{error}</div>}
          </div>
          <form className="cyber-chat-compose" onSubmit={onSubmit}>
            <textarea value={input} onChange={(e) => setInput(e.target.value)} onKeyDown={onKeyDown} placeholder="اكتب سؤالك عن الأمن السيبراني..." rows={1} maxLength={6000} disabled={busy} />
            <button type="submit" aria-label="إرسال الرسالة" disabled={busy || !input.trim()}><Send size={17} /></button>
          </form>
          <div className="cyber-chat-foot">إجابات تعليمية ودفاعية • لا تنفذ هذه الدردشة عمليات فحص</div>
        </section>
      )}
      <button type="button" className={open ? "cyber-chat-launcher active" : "cyber-chat-launcher"} onClick={() => setOpen((value) => !value)} aria-label={open ? "إغلاق Cyber AI Assistant" : "فتح Cyber AI Assistant"}>
        {open ? <X size={22} /> : <><Bot size={22} /><span>اسأل Cyber AI</span><i /></>}
      </button>
    </>
  );
}
