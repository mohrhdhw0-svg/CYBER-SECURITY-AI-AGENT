import { NextRequest, NextResponse } from "next/server";
import {
  setAdminSession,
  validSecret,
  checkLoginRateLimit,
  clearLoginRateLimit,
} from "@/app/lib/approval-store";
import { readBodyWithLimit } from "@/app/lib/read-body-with-limit.js";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

function jsonError(message: string, status: number) {
  return NextResponse.json(
    { error: message },
    { status, headers: { "Cache-Control": "no-store" } },
  );
}

export async function POST(req: NextRequest) {
  const origin = req.headers.get("origin");
  if (origin && origin !== req.nextUrl.origin) {
    return jsonError("مصدر الطلب غير مسموح.", 403);
  }

  const expected = process.env.ADMIN_PANEL_PASSWORD;
  if (!expected || !process.env.ADMIN_SESSION_SECRET) {
    return jsonError("لم يتم إعداد دخول الإدارة.", 503);
  }

  // Trust only the edge-generated Vercel IP header. If it is absent,
  // use a shared bucket rather than a client-spoofable forwarding header.
  const clientKey = (req.headers.get("x-vercel-forwarded-for") || "unknown")
    .split(",")[0]
    .trim()
    .slice(0, 100) || "unknown";

  let limit;
  try {
    limit = await checkLoginRateLimit(clientKey);
  } catch {
    return jsonError("خدمة الحماية غير متاحة حالياً.", 503);
  }
  if (!limit.allowed) {
    return jsonError("محاولات كثيرة. حاول مجدداً بعد 15 دقيقة.", 429);
  }

  let body: unknown;
  try {
    const rawBody = await readBodyWithLimit(req, 8_192);
    if (rawBody === null) return jsonError("حجم الطلب أكبر من الحد المسموح.", 413);
    body = JSON.parse(rawBody);
  } catch {
    return jsonError("طلب غير صالح.", 400);
  }

  if (
    !body ||
    typeof body !== "object" ||
    Array.isArray(body) ||
    Object.keys(body).some((key) => key !== "password") ||
    typeof (body as { password?: unknown }).password !== "string" ||
    (body as { password: string }).password.length > 4_096
  ) {
    return jsonError("بيانات تسجيل الدخول غير صالحة.", 400);
  }

  if (!validSecret((body as { password: string }).password, expected)) {
    return jsonError("كلمة المرور غير صحيحة.", 401);
  }

  try {
    await clearLoginRateLimit(clientKey);
    await setAdminSession();
  } catch {
    return jsonError("تعذر إنشاء جلسة الإدارة بأمان.", 503);
  }

  return NextResponse.json(
    { ok: true },
    { headers: { "Cache-Control": "no-store" } },
  );
}
