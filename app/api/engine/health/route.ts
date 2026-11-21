import { NextResponse } from "next/server";
import { readBodyWithLimit } from "@/app/lib/read-body-with-limit.js";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

function healthResponse(body: Record<string, unknown>, status = 200) {
  return NextResponse.json(body, {
    status,
    headers: { "Cache-Control": "no-store" },
  });
}

export async function GET() {
  const raw = process.env.ENGINE_URL;
  const token = process.env.ENGINE_API_TOKEN;
  if (!raw || !token) {
    return healthResponse({
      configured: false,
      status: "not_configured",
      message: "أضف ENGINE_URL وENGINE_API_TOKEN في إعدادات الخادم.",
    });
  }

  let endpoint: URL;
  try {
    endpoint = new URL(raw);
  } catch {
    return healthResponse({
      configured: true,
      status: "unreachable",
      message: "عنوان محرك الفحص غير صالح.",
    });
  }

  const localHost = ["localhost", "127.0.0.1", "[::1]"].includes(endpoint.hostname);
  const localHttp =
    process.env.NODE_ENV !== "production" &&
    endpoint.protocol === "http:" &&
    localHost;

  if (
    endpoint.username ||
    endpoint.password ||
    endpoint.search ||
    endpoint.hash ||
    (endpoint.protocol !== "https:" && !localHttp)
  ) {
    return healthResponse({
      configured: true,
      status: "unreachable",
      message: "عنوان محرك الفحص يجب أن يكون HTTPS صالحاً.",
    });
  }

  endpoint.pathname = endpoint.pathname.replace(/\/+$/, "") + "/health";

  try {
    const response = await fetch(endpoint, {
      headers: { Authorization: `Bearer ${token}` },
      cache: "no-store",
      redirect: "error",
      signal: AbortSignal.timeout(5_000),
    });

    if (!response.ok) {
      await response.body?.cancel().catch(() => {});
      return healthResponse({
        configured: true,
        status: "unreachable",
        message: "محرك الفحص غير متاح حالياً.",
      });
    }

    const contentLength = Number(response.headers.get("content-length") || 0);
    if (Number.isFinite(contentLength) && contentLength > 16_384) {
      await response.body?.cancel().catch(() => {});
      return healthResponse({
        configured: true,
        status: "unreachable",
        message: "استجابة محرك الفحص غير صالحة.",
      });
    }

    const rawBody = await readBodyWithLimit(response, 16_384);
    if (rawBody === null) {
      return healthResponse({
        configured: true,
        status: "unreachable",
        message: "استجابة محرك الفحص أكبر من الحد المسموح.",
      });
    }

    const data: unknown = JSON.parse(rawBody);
    if (!data || typeof data !== "object" || Array.isArray(data)) {
      throw new Error("Invalid engine health response.");
    }

    const health = data as {
      status?: unknown;
      execution_enabled?: unknown;
      message?: unknown;
    };

    return healthResponse({
      configured: true,
      status: health.status === "ok" ? "ok" : "unreachable",
      execution_enabled: health.execution_enabled === true,
      message:
        typeof health.message === "string"
          ? health.message.slice(0, 240)
          : health.status === "ok"
            ? "محرك الفحص متصل."
            : "محرك الفحص غير جاهز.",
    });
  } catch {
    return healthResponse({
      configured: true,
      status: "unreachable",
      message: "تعذر الاتصال بمحرك الفحص الخاص.",
    });
  }
}
