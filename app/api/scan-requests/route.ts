import { NextRequest, NextResponse } from "next/server";
import { isIPv4 } from "node:net";
import { randomBytes, createHmac, timingSafeEqual } from "node:crypto";
import { saveRequest, newId, getRequest } from "@/app/lib/approval-store";
import { readBodyWithLimit } from "@/app/lib/read-body-with-limit.js";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

function jsonError(message: string, status: number) {
  return NextResponse.json(
    { error: message },
    { status, headers: { "Cache-Control": "no-store" } },
  );
}

function publicIPv4(value: string) {
  if (!isIPv4(value)) return false;
  const [a, b, c] = value.split(".").map(Number);
  // Deny special-purpose, private, loopback, link-local, documentation,
  // benchmarking, multicast, and reserved ranges. This intentionally errs
  // on the side of rejecting unusual addresses for a public scan workflow.
  return !(
    a === 0 ||
    a === 10 ||
    a === 127 ||
    a >= 224 ||
    (a === 100 && b >= 64 && b <= 127) ||
    (a === 169 && b === 254) ||
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && b === 0) ||
    (a === 192 && b === 2) ||
    (a === 192 && b === 88 && c === 99) ||
    (a === 192 && b === 168) ||
    (a === 198 && (b === 18 || b === 19)) ||
    (a === 198 && b === 51 && c === 100) ||
    (a === 203 && b === 0 && c === 113)
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
  if (!publicIPv4(ip)) {
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
  const [ticket, id] = raw.split(".");
  if (!ticket || !id) return jsonError("لا يوجد طلب مرتبط بهذا المتصفح.", 404);

  const secret = process.env.ADMIN_SESSION_SECRET;
  if (!secret) return jsonError("النظام غير مهيأ.", 503);

  try {
    const item = await getRequest(id);
    if (!item) return jsonError("الطلب غير موجود أو انتهت صلاحيته.", 404);

    const proof = createHmac("sha256", secret)
      .update(ticket + "." + id)
      .digest("hex");
    if (
      !item.ticketProof ||
      proof.length !== item.ticketProof.length ||
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
