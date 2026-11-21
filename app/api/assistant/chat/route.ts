import { NextRequest, NextResponse } from "next/server";
import { checkAssistantRateLimit } from "@/app/lib/assistant-rate-limit";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";
export const maxDuration = 60;

const SYSTEM_PROMPT = `أنت Cyber AI Assistant، المساعد التعليمي والدفاعي الرسمي لمنصة CYBER-SECURITY-AI-AGENT.
تخصصك الأمن السيبراني والحماية والاستجابة للحوادث والتعلم داخل المختبرات المصرح بها.
أجب بلغة المستخدم، واجعل العربية هي الافتراضية. كن دقيقاً ومنظماً، واشرح المصطلحات للمبتدئين عند الحاجة.
ساعد في تقوية الأنظمة والشبكات، تحليل السجلات والشفرة، فهم CVE، اكتشاف الثغرات وإصلاحها، إعداد المختبرات، واستخدام أدوات الدفاع والاختبار المصرح.
لا تدّع أنك نفذت فحصاً أو تحققت من نظام أو مصدر مباشر ما لم يحدث ذلك فعلاً. ميّز بين الحقائق والاحتمالات، واطلب السياق الناقص عند الحاجة.
لا تقدم إرشادات عملية لسرقة الحسابات أو بيانات الاعتماد، تجاوز المصادقة، نشر البرمجيات الخبيثة، التخفي أو الاستمرارية، أو اختراق أنظمة دون تصريح. عند الطلبات الخطرة، ارفض الجزء الضار ووجّه إلى بديل دفاعي أو مختبري آمن.
أنت مساعد محادثة فقط: لا تملك وصولاً مباشراً إلى أدوات الفحص أو ملفات المستخدم أو الإنترنت من خلال هذه الواجهة.`;

function jsonError(message: string, status: number) {
  return NextResponse.json({ error: message }, { status, headers: { "Cache-Control": "no-store" } });
}

async function readBodyWithLimit(request: NextRequest, maxBytes: number): Promise<string | null> {
  if (!request.body) return "";
  const reader = request.body.getReader();
  const chunks: Uint8Array[] = [];
  let totalBytes = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      totalBytes += value.byteLength;
      if (totalBytes > maxBytes) {
        await reader.cancel();
        return null;
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }

  const body = new Uint8Array(totalBytes);
  let offset = 0;
  for (const chunk of chunks) {
    body.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return new TextDecoder("utf-8", { fatal: true }).decode(body);
}

export async function GET() {
  const configured = Boolean(
    process.env.AI_API_BASE_URL &&
    process.env.AI_API_KEY &&
    process.env.AI_MODEL &&
    process.env.UPSTASH_REDIS_REST_URL &&
    process.env.UPSTASH_REDIS_REST_TOKEN &&
    process.env.ADMIN_SESSION_SECRET
  );
  return NextResponse.json({
    configured,
    provider: configured ? "openai-compatible" : null,
    message: configured ? "إعدادات مزود الذكاء الاصطناعي والحماية موجودة؛ لم يتم اختبار الاتصال بعد." : "يلزم إعداد AI_API_BASE_URL وAI_API_KEY وAI_MODEL، مع إعداد Redis وحماية الجلسات."
  }, { headers: { "Cache-Control": "no-store" } });
}

export async function POST(request: NextRequest) {
  const origin = request.headers.get("origin");
  if (origin && origin !== request.nextUrl.origin) {
    return jsonError("مصدر الطلب غير مسموح.", 403);
  }

  const baseUrl = process.env.AI_API_BASE_URL;
  const apiKey = process.env.AI_API_KEY;
  const model = process.env.AI_MODEL;
  if (!baseUrl || !apiKey || !model) {
    return jsonError("مساعد الذكاء الاصطناعي غير مهيأ بعد. أضف إعدادات AI_API_BASE_URL وAI_API_KEY وAI_MODEL إلى متغيرات الخادم.", 503);
  }

  let endpoint: URL;
  try {
    const base = new URL(baseUrl);
    const localDevelopmentHost = ["localhost", "127.0.0.1", "[::1]"].includes(base.hostname);
    if (base.username || base.password || base.search || base.hash) {
      return jsonError("يجب أن يحتوي AI_API_BASE_URL على عنوان أساسي فقط دون بيانات دخول أو query أو hash.", 503);
    }
    if (base.protocol !== "https:" && !(process.env.NODE_ENV !== "production" && base.protocol === "http:" && localDevelopmentHost)) {
      return jsonError("يجب أن يستخدم عنوان بوابة الذكاء الاصطناعي HTTPS في بيئة الإنتاج.", 503);
    }
    base.pathname = `${base.pathname.replace(/\/+$/, "")}/chat/completions`;
    endpoint = base;
  } catch {
    return jsonError("قيمة AI_API_BASE_URL غير صالحة.", 503);
  }

  // Vercel overwrites its forwarded client-IP header at the edge to prevent spoofing.
  const clientKey = (
    request.headers.get("x-vercel-forwarded-for") ||
    request.headers.get("x-real-ip") ||
    request.headers.get("x-forwarded-for") ||
    "unknown"
  ).split(",")[0].trim().slice(0, 100);

  try {
    const limit = await checkAssistantRateLimit(clientKey);
    if (!limit.allowed) return jsonError("تم بلوغ حد المحادثات المؤقت. حاول مجدداً بعد 10 دقائق.", 429);
  } catch {
    return jsonError("خدمة الحماية المؤقتة غير متاحة؛ أوقفنا الطلب لحماية الخدمة.", 503);
  }

  const declaredLength = Number(request.headers.get("content-length") || 0);
  if (Number.isFinite(declaredLength) && declaredLength > 100_000) {
    return jsonError("حجم الطلب أكبر من الحد المسموح.", 413);
  }

  let body: unknown;
  try {
    // Enforce the byte limit while streaming, even when Content-Length is absent
    // or falsified by a client or an upstream proxy.
    const rawBody = await readBodyWithLimit(request, 100_000);
    if (rawBody === null) return jsonError("حجم الطلب أكبر من الحد المسموح.", 413);
    body = JSON.parse(rawBody);
  } catch { return jsonError("صيغة الطلب غير صالحة أو غير مشفرة بصيغة UTF-8 صحيحة.", 400); }
  const messages = (body as { messages?: unknown })?.messages;
  if (!Array.isArray(messages) || messages.length < 1 || messages.length > 12) {
    return jsonError("أرسل من رسالة واحدة إلى 12 رسالة في المحادثة.", 400);
  }

  const safeMessages: Array<{ role: "user" | "assistant"; content: string }> = [];
  for (const item of messages) {
    if (!item || typeof item !== "object") return jsonError("تحتوي المحادثة على رسالة غير صالحة.", 400);
    const role = (item as { role?: unknown }).role;
    const content = (item as { content?: unknown }).content;
    if ((role !== "user" && role !== "assistant") || typeof content !== "string" || !content.trim() || content.length > 6000) {
      return jsonError("تحقق من أدوار الرسائل وطول النص؛ الحد الأقصى 6000 حرف للرسالة.", 400);
    }
    safeMessages.push({ role, content: content.trim() });
  }
  if (safeMessages[safeMessages.length - 1]?.role !== "user") {
    return jsonError("يجب أن تنتهي المحادثة برسالة من المستخدم.", 400);
  }

  try {
    const response = await fetch(endpoint, {
      method: "POST",
      headers: { Authorization: `Bearer ${apiKey}`, "Content-Type": "application/json" },
      body: JSON.stringify({
        model,
        messages: [{ role: "system", content: SYSTEM_PROMPT }, ...safeMessages],
        temperature: 0.25,
        max_tokens: 1200,
        stream: false
      }),
      cache: "no-store",
      redirect: "error",
      signal: AbortSignal.timeout(45000)
    });

    if (!response.ok) {
      return jsonError(response.status === 429
        ? "مزود الذكاء الاصطناعي مشغول حالياً. انتظر قليلاً ثم أعد المحاولة."
        : "تعذر الحصول على إجابة من مزود الذكاء الاصطناعي. تحقق من إعدادات البوابة والموديل.", 502);
    }

    // Bound provider response memory use; an upstream gateway must not be able
    // to make this serverless function buffer an unbounded response.
    const declaredResponseLength = Number(response.headers.get("content-length") || 0);
    if (declaredResponseLength > 1_000_000) {
      return jsonError("استجابة مزود الذكاء الاصطناعي أكبر من الحد المسموح.", 502);
    }
    if (!response.body) return jsonError("أعاد مزود الذكاء الاصطناعي استجابة فارغة.", 502);

    const reader = response.body.getReader();
    const decoder = new TextDecoder();
    let responseBytes = 0;
    let responseText = "";
    try {
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        responseBytes += value.byteLength;
        if (responseBytes > 1_000_000) {
          await reader.cancel();
          return jsonError("استجابة مزود الذكاء الاصطناعي أكبر من الحد المسموح.", 502);
        }
        responseText += decoder.decode(value, { stream: true });
      }
      responseText += decoder.decode();
    } finally {
      reader.releaseLock();
    }

    let data: { choices?: Array<{ message?: { content?: unknown } }> };
    try {
      data = JSON.parse(responseText);
    } catch {
      return jsonError("أعاد مزود الذكاء الاصطناعي استجابة غير صالحة.", 502);
    }
    const raw = data?.choices?.[0]?.message?.content;
    const answer = typeof raw === "string"
      ? raw.trim()
      : Array.isArray(raw)
        ? raw.map((part: { type?: string; text?: string }) => part?.type === "text" ? part.text || "" : "").join("\n").trim()
        : "";

    if (!answer) return jsonError("أعاد مزود الذكاء الاصطناعي استجابة فارغة أو بصيغة غير مدعومة.", 502);
    return NextResponse.json({ answer }, { headers: { "Cache-Control": "no-store" } });
  } catch {
    return jsonError("انتهت مهلة الاتصال أو تعذر الوصول إلى مزود الذكاء الاصطناعي.", 504);
  }
}
