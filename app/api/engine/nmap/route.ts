import { NextRequest, NextResponse } from "next/server";
import { isIP } from "node:net";
import { timingSafeEqual } from "node:crypto";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function POST(request: NextRequest) {
  const base = process.env.ENGINE_URL?.replace(/\/$/, "");
  const token = process.env.ENGINE_API_TOKEN;
  const scanKey = process.env.SCAN_ACCESS_KEY;
  const suppliedKey = request.headers.get("x-scan-access-key") || "";
  if (!base || !token || !scanKey) {
    return NextResponse.json({ error: "محرك الفحص غير مهيأ. يجب ضبط أسرار الخادم أولاً." }, { status: 503 });
  }
  const expected = Buffer.from(scanKey);
  const supplied = Buffer.from(suppliedKey);
  if (expected.length !== supplied.length || !timingSafeEqual(expected, supplied)) {
    return NextResponse.json({ error: "مفتاح الوصول غير صحيح." }, { status: 401 });
  }
  let body: { target_ip?: unknown; authorization_reference?: unknown; confirm_authorized?: unknown; top_ports?: unknown };
  try { body = await request.json(); } catch { return NextResponse.json({ error: "طلب JSON غير صالح." }, { status: 400 }); }
  if (typeof body.target_ip !== "string" || isIP(body.target_ip) !== 4) {
    return NextResponse.json({ error: "أدخل عنوان IPv4 حرفياً؛ أسماء النطاقات غير مقبولة في هذا الموصل." }, { status: 400 });
  }
  if (typeof body.authorization_reference !== "string" || body.authorization_reference.trim().length < 4 || body.authorization_reference.length > 120) {
    return NextResponse.json({ error: "أدخل مرجع تصريح صحيحاً (4 إلى 120 حرفاً)." }, { status: 400 });
  }
  if (body.confirm_authorized !== true) return NextResponse.json({ error: "يجب تأكيد امتلاك التصريح أو التفويض المكتوب." }, { status: 400 });
  const topPorts = typeof body.top_ports === "number" ? Math.max(10, Math.min(100, Math.floor(body.top_ports))) : 100;
  try {
    const response = await fetch(`${base}/scans/nmap`, {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` },
      body: JSON.stringify({ ...body, target_ip: body.target_ip.trim(), authorization_reference: body.authorization_reference.trim(), top_ports: topPorts }),
      cache: "no-store",
      signal: AbortSignal.timeout(100000),
    });
    const data = await response.json().catch(() => ({ error: "استجابة غير مفهومة من محرك الفحص." }));
    return NextResponse.json(data, { status: response.status });
  } catch {
    return NextResponse.json({ error: "تعذر الوصول إلى محرك الفحص. تحقق من تشغيله وإعداد الشبكة الخاصة." }, { status: 502 });
  }
}
