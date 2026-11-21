import { handleCallback } from "@vercel/queue";
import { randomBytes } from "node:crypto";
import {
  claimScanLease,
  releaseScanLease,
  getRequest,
  updateRequest,
  createScanPermit,
} from "@/app/lib/approval-store";
import { readBodyWithLimit } from "@/app/lib/read-body-with-limit.js";
import { validScanResult } from "@/app/lib/stored-scan-request.js";

export const runtime = "nodejs";
export const maxDuration = 180;

type ScanMessage = { requestId: string };

function getEngineEndpoint() {
  const raw = process.env.ENGINE_URL;
  if (!raw) throw new Error("Scan engine configuration is incomplete.");

  let endpoint: URL;
  try {
    endpoint = new URL(raw);
  } catch {
    throw new Error("Scan engine URL is invalid.");
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
    throw new Error("Scan engine must use a valid HTTPS URL.");
  }

  endpoint.pathname = endpoint.pathname.replace(/\/+$/, "") + "/scans/intel";
  return endpoint;
}

export const POST = handleCallback(
  async (message: ScanMessage, metadata) => {
    if (
      !message ||
      typeof message.requestId !== "string" ||
      !/^[a-f0-9]{36}$/.test(message.requestId)
    ) {
      // Malformed queue payloads are poison messages; acknowledge without
      // touching any stored request.
      return;
    }

    const item = await getRequest(message.requestId);
    if (
      !item ||
      item.status === "completed" ||
      item.status === "rejected" ||
      item.status === "failed"
    ) {
      return;
    }
    if (item.status !== "scanning") return;

    const leaseToken = randomBytes(24).toString("hex");
    if (!(await claimScanLease(item.id, leaseToken))) {
      throw new Error("Scan is already being processed; retry later.");
    }

    try {
      const current = await getRequest(item.id);
      if (!current || current.status !== "scanning") return;

      const token = process.env.ENGINE_API_TOKEN;
      if (
        !token ||
        !current.expiresAt ||
        !process.env.SCAN_APPROVAL_SECRET ||
        current.authorizationReference !== "admin-approved:" + current.id
      ) {
        throw new Error("Scan engine configuration is incomplete.");
      }

      const endpoint = getEngineEndpoint();
      const permit = createScanPermit(current.ip, current.id, current.expiresAt);

      const response = await fetch(endpoint, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${token}`,
          "X-Scan-Approval": permit,
        },
        body: JSON.stringify({
          target_ip: current.ip,
          authorization_reference: current.authorizationReference,
          confirm_authorized: true,
          top_ports: 100,
        }),
        cache: "no-store",
        redirect: "error",
        signal: AbortSignal.timeout(115_000),
      });

      const contentLength = Number(response.headers.get("content-length") || 0);
      if (Number.isFinite(contentLength) && contentLength > 1_048_576) {
        await response.body?.cancel().catch(() => {});
        throw new Error("Scan engine response exceeded the allowed size.");
      }

      const responseText = await readBodyWithLimit(response, 1_048_576);
      if (responseText === null) {
        throw new Error("Scan engine response exceeded the allowed size.");
      }

      let data: unknown;
      try {
        data = JSON.parse(responseText);
      } catch {
        throw new Error("Scan engine returned an invalid response.");
      }

      if (!response.ok) {
        if (
          response.status === 408 ||
          response.status === 409 ||
          response.status === 429 ||
          response.status >= 500
        ) {
          throw new Error(`Scan engine temporarily unavailable (HTTP ${response.status}).`);
        }

        const detail =
          data && typeof data === "object"
            ? (data as { detail?: unknown; error?: unknown }).detail ??
              (data as { error?: unknown }).error
            : undefined;
        current.status = "failed";
        current.error =
          typeof detail === "string"
            ? detail.slice(0, 1_000)
            : `Scan engine rejected the request (HTTP ${response.status}).`;
        await updateRequest(current);
        return;
      }

      if (!validScanResult(data, current.ip, current.authorizationReference ?? "")) {
        throw new Error("Scan engine returned a result that failed validation.");
      }

      current.status = "completed";
      current.result = data;
      delete current.error;
      await updateRequest(current);
    } catch (error) {
      // After repeated delivery failures, persist a terminal state rather than
      // acknowledging the message while leaving the UI stuck on "scanning".
      if (metadata.deliveryCount >= 8) {
        const latest = await getRequest(item.id);
        if (latest?.status === "scanning") {
          latest.status = "failed";
          latest.error = "تعذر إكمال الفحص بعد عدة محاولات. راجع اتصال المحرك وإعداداته ثم أعد إرسال الطلب.";
          await updateRequest(latest);
          return;
        }
      }
      throw error;
    } finally {
      await releaseScanLease(item.id, leaseToken);
    }
  },
  {
    visibilityTimeoutSeconds: 180,
    retry: (_error, metadata) => ({
      afterSeconds: Math.min(300, Math.max(15, metadata.deliveryCount * 15)),
    }),
  },
);
