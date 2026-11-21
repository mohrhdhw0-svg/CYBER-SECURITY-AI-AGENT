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
  return NextResponse.json({ error: message }, { status });
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
    message: configured ? "مساعد الذكاء الاصطناعي جاهز لاستقبال الأسئلة." : "يلزم إعداد AI_API_BASE_URL وAI_API_KEY وAI_MODEL، مع إعداد Redis وحماية الجلسات."
  }, { headers: { "Cache-Control": "no-store" } });
}

export async function POST(request: NextRequest) {
  const origin = request.headers.get("origin");
  if (origin && origin !== request.nextUrl.origin) {
    return jsonError("مصدر الطلب غير مسموح.", 403);
  }

  const baseUrl = process.env.AI_API_BASE_URL?.replace(/\/$/, "");
  const apiKey = process.env.AI_API_KEY;
  const model = process.env.AI_MODEL;
  if (!baseUrl || !apiKey || !model) {
    return jsonError("مساعد الذكاء الاصطناعي غير مهيأ بعد. أضف إعدادات AI_API_BASE_URL وAI_API_KEY وAI_MODEL إلى متغيرات الخادم.", 503);
  }

  let endpoint: URL;
  try {
    endpoint = new URL(`${baseUrl}/chat/completions`);
    if (endpoint.protocol !== "https:" && endpoint.hostname !== "localhost" && endpoint.hostname !== "127.0.0.1") {
      return jsonError("يجب أن يستخدم عنوان بوابة الذكاء الاصطناعي اتصال HTTPS.", 503);
    }
  } catch {
    return jsonError("قيمة AI_API_BASE_URL غير صالحة.", 503);
  }

  const clientKey = (request.headers.get("x-forwarded-for") || request.headers.get("x-real-ip") || "unknown").split(",")[0].trim().slice(0, 100);
  try {
    const limit = await checkAssistantRateLimit(clientKey);
    if (!limit.allowed) return jsonError("تم بلوغ حد المحادثات المؤقت. حاول مجدداً بعد 10 دقائق.", 429);
  } catch {
    return jsonError("خدمة الحماية المؤقتة غير متاحة؛ أوقفنا الطلب لحماية الخدمة.", 503);
  }

  let body: unknown;
  try { body = await request.json(); } catch { return jsonError("صيغة الطلب غير صالحة.", 400); }
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
      signal: AbortSignal.timeout(45000)
    });

    if (!response.ok) {
      return jsonError(response.status === 429
        ? "مزود الذكاء الاصطناعي مشغول حالياً. انتظر قليلاً ثم أعد المحاولة."
        : "تعذر الحصول على إجابة من مزود الذكاء الاصطناعي. تحقق من إعدادات البوابة والموديل.", 502);
    }

    const data = await response.json();
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
