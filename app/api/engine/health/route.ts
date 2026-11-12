import { NextResponse } from "next/server";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function GET() {
  const base = process.env.ENGINE_URL?.replace(/\/$/, "");
  const token = process.env.ENGINE_API_TOKEN;
  if (!base || !token) {
    return NextResponse.json({ configured: false, status: "not_configured", message: "أضف ENGINE_URL وENGINE_API_TOKEN في إعدادات الخادم." }, { status: 200 });
  }
  try {
    const response = await fetch(`${base}/health`, {
      headers: { Authorization: `Bearer ${token}` },
      cache: "no-store",
      signal: AbortSignal.timeout(5000),
    });
    if (!response.ok) return NextResponse.json({ configured: true, status: "unreachable", message: `محرك الفحص أعاد HTTP ${response.status}` }, { status: 200 });
    const data = await response.json();
    return NextResponse.json({ configured: true, ...data }, { status: 200 });
  } catch {
    return NextResponse.json({ configured: true, status: "unreachable", message: "تعذر الاتصال بمحرك الفحص الخاص." }, { status: 200 });
  }
}
