import { NextRequest, NextResponse } from "next/server";
import { send } from "@vercel/queue";
import {
  isAdmin,
  listRequests,
  getRequest,
  updateRequest,
  transitionPendingRequest,
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

export async function GET() {
  if (!(await isAdmin())) return jsonError("غير مصرح.", 401);
  try {
    return NextResponse.json(
      { requests: await listRequests() },
      { headers: { "Cache-Control": "no-store" } },
    );
  } catch {
    return jsonError("مخزن الموافقات غير مهيأ أو غير متاح.", 503);
  }
}

export async function POST(req: NextRequest) {
  const origin = req.headers.get("origin");
  if (origin && origin !== req.nextUrl.origin) {
    return jsonError("مصدر الطلب غير مسموح.", 403);
  }
  if (!(await isAdmin())) return jsonError("غير مصرح.", 401);

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
    Object.keys(body).some((key) => key !== "id" && key !== "action") ||
    typeof (body as { id?: unknown }).id !== "string" ||
    !/^[a-f0-9]{36}$/.test((body as { id: string }).id) ||
    !["approve", "reject"].includes(String((body as { action?: unknown }).action))
  ) {
    return jsonError("بيانات القرار غير صالحة.", 400);
  }

  const { id, action } = body as { id: string; action: "approve" | "reject" };

  try {
    const item = await getRequest(id);
    if (!item) return jsonError("الطلب غير موجود.", 404);
    if (item.status !== "pending") {
      return jsonError("تم اتخاذ قرار لهذا الطلب مسبقاً.", 409);
    }

    item.decisionAt = new Date().toISOString();

    if (action === "reject") {
      item.status = "rejected";
      if (!(await transitionPendingRequest(item))) {
        return jsonError("تم اتخاذ قرار لهذا الطلب مسبقاً.", 409);
      }
      return NextResponse.json(
        { request: item },
        { headers: { "Cache-Control": "no-store" } },
      );
    }

    if (
      !process.env.ENGINE_URL ||
      !process.env.ENGINE_API_TOKEN ||
      !process.env.SCAN_APPROVAL_SECRET
    ) {
      return jsonError(
        "محرك الفحص أو أسرار الموافقات غير مهيأة؛ لم يبدأ الفحص.",
        503,
      );
    }

    item.status = "scanning";
    item.expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString();
    item.authorizationReference = "admin-approved:" + item.id;
    delete item.error;

    if (!(await transitionPendingRequest(item))) {
      return jsonError("تم اتخاذ قرار لهذا الطلب مسبقاً.", 409);
    }

    try {
      await send(
        "ip-scan-requests",
        { requestId: item.id },
        { idempotencyKey: item.id, retentionSeconds: 86_400 },
      );
    } catch {
      item.status = "failed";
      item.error = "تعذر وضع الفحص في قائمة المهام؛ تحقق من تفعيل Vercel Queues وصلاحيات OIDC.";
      await updateRequest(item);
      return NextResponse.json(
        { request: item, error: item.error },
        { status: 503, headers: { "Cache-Control": "no-store" } },
      );
    }

    return NextResponse.json(
      { request: item, queued: true },
      { status: 202, headers: { "Cache-Control": "no-store" } },
    );
  } catch {
    return jsonError("تعذر تحديث الطلب أو حفظه.", 503);
  }
}
