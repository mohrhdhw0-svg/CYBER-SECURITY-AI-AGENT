"use client";

import { useCallback, useEffect, useState, type FormEvent } from "react";
import {
  Activity,
  CircleAlert,
  CircleCheck,
  LoaderCircle,
  ShieldCheck,
} from "lucide-react";

type Health = {
  status?: string;
  execution_enabled?: boolean;
  message?: string;
};

type Intel = {
  target?: string;
  passive?: {
    rdap?: any;
    routing?: any;
    reverse_dns?: any;
    reputation?: any;
    geo?: any;
    sources?: any[];
    warnings?: string[];
    collected_at?: string;
  };
  ports?: Array<{
    port: string;
    protocol: string;
    state: string;
    service: string;
    product?: string | null;
    version?: string | null;
  }>;
  summary?: { ports_observed: number; open_ports: number };
  limitations?: string[];
};

type RequestStatus = {
  id: string;
  ip: string;
  status: string;
  expiresAt?: string;
  result?: Intel;
  error?: string;
};

export default function EnginePanel() {
  const [health, setHealth] = useState<Health | null>(null);
  const [target, setTarget] = useState("");
  const [requestStatus, setRequestStatus] = useState<RequestStatus | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  const refresh = useCallback(async () => {
    try {
      const response = await fetch("/api/engine/health", { cache: "no-store" });
      if (!response.ok) throw new Error("Health request failed.");
      setHealth(await response.json());
    } catch {
      setHealth({
        status: "unreachable",
        message: "تعذر قراءة حالة المحرك.",
      });
    }
  }, []);

  const refreshApproval = useCallback(async () => {
    try {
      const response = await fetch("/api/scan-requests", { cache: "no-store" });
      const data = await response.json();
      if (response.ok && data.request) {
        setRequestStatus(data.request);
        setTarget(data.request.ip);
      }
    } catch {
      // Keep the last known request state if a transient poll fails.
    }
  }, []);

  useEffect(() => {
    let cancelled = false;

    void fetch("/api/engine/health", { cache: "no-store" })
      .then(async (response) => {
        if (!response.ok) throw new Error("Health request failed.");
        return (await response.json()) as Health;
      })
      .then((data) => {
        if (!cancelled) setHealth(data);
      })
      .catch(() => {
        if (!cancelled) {
          setHealth({
            status: "unreachable",
            message: "تعذر قراءة حالة المحرك.",
          });
        }
      });

    void fetch("/api/scan-requests", { cache: "no-store" })
      .then(async (response) => {
        const data = await response.json();
        if (!response.ok || !data.request) return null;
        return data.request as RequestStatus;
      })
      .then((request) => {
        if (!cancelled && request) {
          setRequestStatus(request);
          setTarget(request.ip);
        }
      })
      .catch(() => {
        // No saved request is a normal first-visit state.
      });

    return () => {
      cancelled = true;
    };
  }, []);

  const activeRequestId = requestStatus?.id;
  const activeRequestStatus = requestStatus?.status;

  useEffect(() => {
    if (
      !activeRequestId ||
      !activeRequestStatus ||
      !["pending", "approved", "scanning"].includes(activeRequestStatus)
    ) {
      return;
    }

    const timer = setInterval(() => void refreshApproval(), 3_000);
    return () => clearInterval(timer);
  }, [activeRequestId, activeRequestStatus, refreshApproval]);

  async function submitRequest(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError("");
    setRequestStatus(null);

    try {
      const response = await fetch("/api/scan-requests", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ ip: target }),
      });
      const data = await response.json();
      if (!response.ok) {
        throw new Error(data.error || "تعذر إرسال الطلب");
      }
      await refreshApproval();
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "حدث خطأ");
    } finally {
      setBusy(false);
    }
  }

  const ready =
    health?.status === "ok" && health?.execution_enabled === true;
  const report = requestStatus?.result;
  const passive = report?.passive;

  return (
    <section className="engine-panel" aria-labelledby="engine-title">
      <div className="engine-heading">
        <div>
          <div className="engine-kicker">
            <Activity size={14} /> LIVE ENGINE CONNECTIVITY
          </div>
          <h2 id="engine-title">محرك استخبارات عناوين IP</h2>
          <p>
            أدخل عنوان IP فقط. بعد موافقة الإدارة يبدأ جمع المعلومات تلقائياً
            دون أي خطوة إضافية منك.
          </p>
        </div>
        <span className={ready ? "engine-state ready" : "engine-state"}>
          {ready ? <CircleCheck size={14} /> : <CircleAlert size={14} />}
          {ready ? "المحرك متصل" : "المحرك غير مهيأ"}
        </span>
      </div>

      <div className="engine-status">
        <span className={ready ? "status-led ready" : "status-led"} />
        <b>
          {health?.message ||
            (ready
              ? "المحرك جاهز وينتظر موافقة الإدارة."
              : "تحقق من إعداد المحرك ومخزن الطلبات.")}
        </b>
        <button type="button" onClick={() => void refresh()}>
          تحديث الحالة
        </button>
      </div>

      <form className="scan-form" onSubmit={submitRequest}>
        <label>
          عنوان IPv4 عام تملكه أو لديك تفويض مكتوب لاختباره
          <input
            value={target}
            onChange={(event) => setTarget(event.target.value)}
            placeholder="أدخل عنوان IP العام"
            inputMode="decimal"
            required
          />
        </label>
        <button
          className="scan-submit"
          type="submit"
          disabled={busy || !target.trim()}
        >
          {busy ? (
            <>
              <LoaderCircle className="spin" size={17} /> جارٍ الإرسال...
            </>
          ) : (
            <>
              <ShieldCheck size={17} /> إرسال طلب الفحص
            </>
          )}
        </button>
      </form>

      {requestStatus && (
        <div className="engine-help">
          <b>
            حالة الطلب:{" "}
            {(
              {
                pending: "بانتظار موافقة الإدارة",
                approved: "تمت الموافقة",
                scanning: "تمت الموافقة — يجري البحث تلقائياً",
                completed: "اكتمل البحث والتقرير جاهز",
                rejected: "تم رفض الطلب",
                failed: "تعذر إكمال البحث",
              } as Record<string, string>
            )[requestStatus.status] || requestStatus.status}
          </b>
          <p>العنوان: {requestStatus.ip}</p>
          {requestStatus.status === "scanning" && (
            <p>
              <LoaderCircle className="spin" size={15} /> يجري جمع معلومات
              الشبكة وفحص المنافذ المحددة...
            </p>
          )}
          {requestStatus.error && <p role="alert">{requestStatus.error}</p>}
        </div>
      )}

      {report && (
        <div className="scan-results">
          <h3>تقرير استخبارات IP — {report.target}</h3>
          <p>
            وقت الجمع: {passive?.collected_at || "غير متاح"} · المنافذ
            المفتوحة: {report.summary?.open_ports ?? 0} من{" "}
            {report.summary?.ports_observed ?? 0} مرصود
          </p>
          <h4>معلومات التسجيل والشبكة (RDAP)</h4>
          <pre>
            {passive?.rdap
              ? JSON.stringify(
                  {
                    name: passive.rdap.name,
                    handle: passive.rdap.handle,
                    port43: passive.rdap.port43,
                    remarks: passive.rdap.remarks,
                    entities: passive.rdap.entities?.map(
                      (entity: any) => entity.roles,
                    ),
                  },
                  null,
                  2,
                )
              : "لم تتوفر بيانات RDAP."}
          </pre>
          <h4>ASN والتوجيه</h4>
          <pre>{JSON.stringify(passive?.routing || {}, null, 2)}</pre>
          <h4>الموقع التقريبي ومزود الشبكة</h4>
          <pre>{JSON.stringify(passive?.geo || {}, null, 2)}</pre>
          <h4>DNS العكسي</h4>
          <pre>{JSON.stringify(passive?.reverse_dns || {}, null, 2)}</pre>
          <h4>سمعة العنوان</h4>
          <pre>{JSON.stringify(passive?.reputation || {}, null, 2)}</pre>
          <h4>المنافذ والخدمات المكتشفة</h4>
          {(report.ports || []).length ? (
            <div className="scan-table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>المنفذ</th>
                    <th>الحالة</th>
                    <th>الخدمة</th>
                    <th>المنتج والإصدار</th>
                  </tr>
                </thead>
                <tbody>
                  {report.ports?.map((port, index) => (
                    <tr key={port.protocol + port.port + index}>
                      <td>
                        {port.port}/{port.protocol}
                      </td>
                      <td>{port.state}</td>
                      <td>{port.service}</td>
                      <td>
                        {[port.product, port.version].filter(Boolean).join(" ") ||
                          "غير محدد"}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <p>لم تُرصد منافذ ضمن النطاق المحدد.</p>
          )}
          <h4>مصادر وحدود التقرير</h4>
          <ul>
            {(passive?.sources || []).map((source: any) => (
              <li key={source.name}>{source.name}</li>
            ))}
            {(report.limitations || []).map((limitation, index) => (
              <li key={index}>{limitation}</li>
            ))}
            {(passive?.warnings || []).map((warning, index) => (
              <li key={"w" + index}>{warning}</li>
            ))}
          </ul>
        </div>
      )}

      {!ready && (
        <div className="engine-help">
          <ShieldCheck size={17} /> الفحص الفعلي لن يعمل حتى تكتمل إعدادات
          المحرك ومخزن الطلبات والأسرار.
        </div>
      )}
      {error && (
        <div className="scan-error" role="alert">
          {error}
        </div>
      )}
    </section>
  );
}
