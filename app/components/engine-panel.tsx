"use client";

import { useEffect, useState, type FormEvent } from "react";
import { Activity, CircleAlert, CircleCheck, LoaderCircle, Radar, ShieldCheck } from "lucide-react";

type Health = { configured?: boolean; status?: string; execution_enabled?: boolean; message?: string };
type Scan = { status?: string; target?: string; authorization_reference?: string; ports?: Array<{port:string;protocol:string;state:string;service:string;product?:string|null;version?:string|null}>; summary?: {ports_observed:number}; error?: string; detail?: string };

export default function EnginePanel() {
  const [health,setHealth] = useState<Health | null>(null);
  const [target,setTarget] = useState("");
  const [reference,setReference] = useState("");
  const [accessKey,setAccessKey] = useState("");
  const [confirmed,setConfirmed] = useState(false);
  const [busy,setBusy] = useState(false);
  const [error,setError] = useState("");
  const [result,setResult] = useState<Scan | null>(null);

  async function refresh() {
    try { const r = await fetch("/api/engine/health",{cache:"no-store"}); setHealth(await r.json()); }
    catch { setHealth({status:"unreachable",message:"تعذر قراءة حالة المحرك."}); }
  }
  useEffect(()=>{ void refresh(); },[]);

  async function runScan(e: FormEvent<HTMLFormElement>) {
    e.preventDefault(); setBusy(true); setError(""); setResult(null);
    try {
      const r = await fetch("/api/engine/nmap",{method:"POST",headers:{"Content-Type":"application/json","x-scan-access-key":accessKey},body:JSON.stringify({target_ip:target,authorization_reference:reference,confirm_authorized:confirmed,top_ports:100})});
      const data = await r.json();
      if (!r.ok) throw new Error(data.error || data.detail || "فشل تنفيذ الفحص.");
      setResult(data);
    } catch (err) { setError(err instanceof Error ? err.message : "حدث خطأ غير متوقع."); }
    finally { setBusy(false); }
  }

  const ready = health?.status === "ok" && health?.execution_enabled === true;
  return <section className="engine-panel" aria-labelledby="engine-title">
    <div className="engine-heading"><div><div className="engine-kicker"><Activity size={14}/> LIVE ENGINE CONNECTIVITY</div><h2 id="engine-title">محرك الفحص الفعلي</h2><p>موصل Nmap محدود، يعمل عبر خدمة Docker منفصلة ولا ينفذ أوامر عامة.</p></div>
      <span className={ready ? "engine-state ready" : "engine-state"}>{ready ? <CircleCheck size={14}/> : <CircleAlert size={14}/>} {ready ? "متصل ومهيأ" : "بانتظار إعداد المحرك"}</span>
    </div>
    <div className="engine-status"><span className={ready ? "status-led ready" : "status-led"}/><b>{health?.message || (ready ? "قائمة السماح مهيأة والتنفيذ متاح." : health?.status === "unreachable" ? "المحرك غير متاح حالياً." : "خدمة الفحص لم تُربط بعد.")}</b><button type="button" onClick={()=>void refresh()}>تحديث الحالة</button></div>
    <form className="scan-form" onSubmit={runScan}>
      <label>عنوان IPv4 للمختبر<input value={target} onChange={e=>setTarget(e.target.value)} placeholder="مثال: عنوان جهاز مختبرك" inputMode="decimal" required/></label>
      <label>مفتاح تشغيل الفحص<input type="password" value={accessKey} onChange={e=>setAccessKey(e.target.value)} placeholder="أدخل مفتاح SCAN_ACCESS_KEY" autoComplete="off" required/></label>
      <label>مرجع التفويض<input value={reference} onChange={e=>setReference(e.target.value)} placeholder="رقم موافقة المختبر أو وصفها" minLength={4} maxLength={120} required/></label>
      <label className="authorization-check"><input type="checkbox" checked={confirmed} onChange={e=>setConfirmed(e.target.checked)}/> أؤكد أن هذا الهدف أملكه أو لدي تفويض مكتوب لاختباره.</label>
      <button className="scan-submit" type="submit" disabled={!ready || busy || !confirmed || !target || accessKey.length<20 || reference.trim().length<4}>{busy ? <><LoaderCircle className="spin" size={17}/> جارٍ تنفيذ الفحص...</> : <><Radar size={17}/> فحص الخدمات المصرح بها</>}</button>
    </form>
    {!ready && <div className="engine-help"><ShieldCheck size={17}/> لن يُرسل أي فحص قبل إعداد عنوان المحرك ورمزه السري وقائمة عناوين IP المسموح بها على الخادم الخاص.</div>}
    {error && <div className="scan-error" role="alert">{error}</div>}
    {result && <div className="scan-results"><h3>نتيجة الفحص — {result.target}</h3><p>الخدمات المرصودة: {result.summary?.ports_observed ?? result.ports?.length ?? 0}</p>{(result.ports || []).length ? <div className="scan-table-wrap"><table><thead><tr><th>المنفذ</th><th>الحالة</th><th>الخدمة</th><th>المنتج والإصدار</th></tr></thead><tbody>{result.ports?.map((p,i)=><tr key={p.protocol+p.port+i}><td>{p.port}/{p.protocol}</td><td>{p.state}</td><td>{p.service}</td><td>{[p.product,p.version].filter(Boolean).join(" ") || "غير محدد"}</td></tr>)}</tbody></table></div>:<p>لم تُرصد منافذ مفتوحة ضمن نطاق الفحص المحدد.</p>}</div>}
  </section>;
}
