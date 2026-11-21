import { NextRequest, NextResponse } from "next/server";
import { randomBytes, createHmac, timingSafeEqual } from "node:crypto";
import { saveRequest, newId, getRequest } from "@/app/lib/approval-store";
import { readBodyWithLimit } from "@/app/lib/read-body-with-limit.js";
import { isPublicIPv4 } from "@/app/lib/public-ipv4.js";

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
    Object.keys(body).some((key) => key !== "ip") ||
    typeof (body as { ip?: unknown }).ip !== "string"
  ) {
    return jsonError("بيانات الطلب غير صالحة.", 400);
  }

  const ip = (body as { ip: string }).ip.trim();
  if (!isPublicIPv4(ip)) {
    return jsonError("أدخل عنوان IPv4 عاماً صالحاً؛ العناوين الخاصة والمحجوزة غير مسموحة.", 400);
  }

  const secret = process.env.ADMIN_SESSION_SECRET;
  if (!secret) return jsonError("النظام غير مهيأ.", 503);

  try {
    const id = newId();
    const ticket = randomBytes(32).toString("hex");
    const proof = createHmac("sha256", secret)
      .update(ticket + "." + id)
      .digest("hex");

    await saveRequest({
      id,
      ip,
      status: "pending",
      createdAt: new Date().toISOString(),
      ticketProof: proof,
    });

    const response = NextResponse.json(
      {
        ok: true,
        status: "pending",
        requestId: id,
        message: "تم إرسال الطلب إلى لوحة الإدارة للمراجعة.",
      },
      { headers: { "Cache-Control": "no-store" } },
    );
    response.cookies.set("scan_ticket", ticket + "." + id, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "strict",
      path: "/",
      maxAge: 7 * 24 * 60 * 60,
    });
    return response;
  } catch {
    return jsonError("تعذر حفظ الطلب. تحقق من إعداد مخزن الموافقات.", 503);
  }
}

export async function GET(req: NextRequest) {
  const raw = req.cookies.get("scan_ticket")?.value || "";
  const parts = raw.split(".");
  if (parts.length !== 2) return jsonError("لا يوجد طلب مرتبط بهذا المتصفح.", 404);
  const [ticket, id] = parts;
  if (!/^[a-f0-9]{64}$/.test(ticket) || !/^[a-f0-9]{36}$/.test(id)) {
    return jsonError("تذكرة الطلب غير صالحة.", 404);
  }

  const secret = process.env.ADMIN_SESSION_SECRET;
  if (!secret) return jsonError("النظام غير مهيأ.", 503);

  try {
    const item = await getRequest(id);
    if (!item) return jsonError("الطلب غير موجود أو انتهت صلاحيته.", 404);

    const proof = createHmac("sha256", secret)
      .update(ticket + "." + id)
      .digest("hex");
    if (
      typeof item.ticketProof !== "string" ||
      !/^[a-f0-9]{64}$/.test(item.ticketProof) ||
      !timingSafeEqual(Buffer.from(proof, "hex"), Buffer.from(item.ticketProof, "hex"))
    ) {
      return jsonError("تعذر التحقق من تذكرة الطلب.", 403);
    }

    return NextResponse.json(
      {
        request: {
          id: item.id,
          ip: item.ip,
          status: item.status,
          expiresAt: item.expiresAt,
          result: item.result,
          error: item.error,
        },
      },
      { headers: { "Cache-Control": "no-store" } },
    );
  } catch {
    return jsonError("مخزن الموافقات غير متاح.", 503);
  }
}
