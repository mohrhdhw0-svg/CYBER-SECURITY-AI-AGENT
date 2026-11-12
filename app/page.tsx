"use client";

import { useMemo, useState } from "react";
import {
  Activity, ShieldCheck, Radar, Bug, Network, Smartphone, Cloud,
  Search, FileText, Settings, LayoutDashboard, Boxes, ChevronLeft,
  CircleCheck, Clock3, AlertTriangle, LockKeyhole, TerminalSquare,
  BrainCircuit, ShieldAlert, Database, Menu, X, Filter
} from "lucide-react";

type Tool = { name: string; category: string; description: string; status: "planned" | "ready"; tag: string };

const tools: Tool[] = [
  {name:"Nmap",category:"الشبكات",description:"اكتشاف الأصول والخدمات داخل النطاق المصرح.",status:"planned",tag:"Network"},
  {name:"Masscan",category:"الشبكات",description:"جرد سريع للمنافذ ضمن نطاق مختبري مضبوط.",status:"planned",tag:"Network"},
  {name:"Wireshark / TShark",category:"الشبكات",description:"تحليل حركة الشبكة وملفات PCAP.",status:"planned",tag:"Traffic"},
  {name:"Zeek",category:"الشبكات",description:"تحليل بروتوكولات الشبكة وإنتاج سجلات أمنية.",status:"planned",tag:"NDR"},
  {name:"Suricata",category:"مراقبة SOC",description:"كشف التهديدات عبر IDS/IPS.",status:"planned",tag:"IDS"},
  {name:"Wazuh",category:"مراقبة SOC",description:"مراقبة الأجهزة وتجميع التنبيهات.",status:"planned",tag:"SIEM"},
  {name:"OWASP ZAP",category:"أمن الويب",description:"اختبار أمان تطبيقات الويب في بيئة مصرح بها.",status:"planned",tag:"DAST"},
  {name:"Burp Suite",category:"أمن الويب",description:"تحليل طلبات HTTP واختبار التطبيقات.",status:"planned",tag:"DAST"},
  {name:"Nuclei",category:"الثغرات",description:"فحوصات مبنية على قوالب قابلة للمراجعة.",status:"planned",tag:"Scanner"},
  {name:"Greenbone / OpenVAS",category:"الثغرات",description:"إدارة وفحص الثغرات للبنية التحتية.",status:"planned",tag:"Scanner"},
  {name:"Trivy",category:"السحابة والحاويات",description:"فحص صور الحاويات والاعتماديات والإعدادات.",status:"planned",tag:"SCA"},
  {name:"Prowler",category:"السحابة والحاويات",description:"تقييم إعدادات خدمات السحابة.",status:"planned",tag:"CSPM"},
  {name:"MobSF",category:"أمن الهاتف",description:"تحليل تطبيقات Android وiOS.",status:"planned",tag:"Mobile"},
  {name:"JADX",category:"أمن الهاتف",description:"فحص وتحليل ملفات APK.",status:"planned",tag:"Mobile"},
  {name:"Ghidra",category:"تحليل البرمجيات",description:"هندسة عكسية وتحليل ثنائيات.",status:"planned",tag:"RE"},
  {name:"YARA",category:"تحليل البرمجيات",description:"مطابقة قواعد كشف البرمجيات المشبوهة.",status:"planned",tag:"Detection"},
  {name:"Volatility 3",category:"الأدلة الرقمية",description:"تحليل تفريغات الذاكرة.",status:"planned",tag:"Forensics"},
  {name:"Autopsy",category:"الأدلة الرقمية",description:"تحليل الأدلة الرقمية والملفات.",status:"planned",tag:"Forensics"},
  {name:"MISP",category:"استخبارات التهديدات",description:"إدارة ومشاركة مؤشرات الاختراق.",status:"planned",tag:"CTI"},
  {name:"OpenCTI",category:"استخبارات التهديدات",description:"ربط معلومات التهديدات وتحليلها.",status:"planned",tag:"CTI"},
  {name:"TheHive",category:"الاستجابة للحوادث",description:"إدارة الحوادث والتحقيقات الأمنية.",status:"planned",tag:"IR"},
  {name:"Sigma",category:"مراقبة SOC",description:"قواعد كشف قابلة للتحويل لمحركات SIEM.",status:"planned",tag:"Detection"},
  {name:"Hashcat",category:"تدقيق كلمات المرور",description:"تدقيق قوة كلمات المرور على عينات مصرح بها.",status:"planned",tag:"Audit"},
  {name:"John the Ripper",category:"تدقيق كلمات المرور",description:"تقييم تجزئات اختبارية في المختبر.",status:"planned",tag:"Audit"},
  {name:"BloodHound",category:"هوية ودليل نشط",description:"رسم علاقات وصلاحيات Active Directory.",status:"planned",tag:"Identity"},
  {name:"Checkov",category:"السحابة والحاويات",description:"فحص البنية التحتية ككود.",status:"planned",tag:"IaC"}
];

const categories = ["الكل", ...Array.from(new Set(tools.map(t => t.category)))];
const nav = [
  {label:"نظرة عامة",icon:LayoutDashboard},
  {label:"كتالوج الأدوات",icon:Boxes},
  {label:"الأصول والنطاقات",icon:Network},
  {label:"مهام الفحص",icon:Radar},
  {label:"مركز SOC",icon:Activity},
  {label:"تحليل البرمجيات",icon:Bug},
  {label:"المختبرات",icon:TerminalSquare},
  {label:"التقارير",icon:FileText}
];

export default function Home() {
  const [query,setQuery] = useState("");
  const [category,setCategory] = useState("الكل");
  const [active,setActive] = useState("نظرة عامة");
  const [mobileOpen,setMobileOpen] = useState(false);
  const filtered = useMemo(() => tools.filter(t =>
    (category === "الكل" || t.category === category) &&
    (t.name + " " + t.description + " " + t.category).toLowerCase().includes(query.toLowerCase())
  ),[query,category]);

  return <main className="shell">
    <aside className={mobileOpen ? "sidebar open" : "sidebar"}>
      <div className="brand"><div className="brand-mark"><ShieldCheck size={24}/></div><div><b>CYBER<span>AI</span></b><small>SECURITY OPERATIONS</small></div><button className="close-menu" onClick={()=>setMobileOpen(false)}><X/></button></div>
      <div className="workspace"><span className="live-dot"/> مساحة العمل الرئيسية <ChevronLeft size={15}/></div>
      <div className="nav-label">مساحة العمل</div>
      {nav.map(({label,icon:Icon})=><button key={label} className={"nav-item "+(active===label?"selected":"")} onClick={()=>{setActive(label);setMobileOpen(false)}}><Icon size={18}/><span>{label}</span>{label==="مهام الفحص"&&<i>0</i>}</button>)}
      <div className="nav-label">الإدارة</div>
      <button className="nav-item"><LockKeyhole size={18}/><span>المستخدمون والصلاحيات</span></button>
      <button className="nav-item"><Settings size={18}/><span>الإعدادات</span></button>
      <div className="sidebar-bottom"><div className="secure-card"><ShieldCheck size={19}/><b>وضع الاستخدام الآمن</b><p>لا تُشغّل الفحوصات إلا على أصول مصرح بها.</p><span>الحماية مفعّلة</span></div><div className="profile"><div className="avatar">CA</div><div><b>مسؤول المنصة</b><small>حساب محلي تجريبي</small></div><Settings size={17}/></div></div>
    </aside>
    {mobileOpen&&<button className="scrim" onClick={()=>setMobileOpen(false)} aria-label="إغلاق القائمة"/>}
    <section className="main">
      <header className="topbar"><button className="menu-btn" onClick={()=>setMobileOpen(true)}><Menu/></button><div className="crumb">مساحة العمل <span>/</span> {active}</div><div className="top-actions"><span className="env"><i/> بيئة تطوير</span><button className="icon-btn"><Activity size={18}/></button><div className="avatar small">CA</div></div></header>
      <div className="content">
        <div className="welcome"><div><div className="eyebrow"><span/> DEFENSIVE SECURITY PLATFORM</div><h1>مركز العمليات الأمنية</h1><p>رؤية موحدة للأصول والفحوصات والأدوات والتحليلات الأمنية.</p></div><div className="date-chip"><Clock3 size={16}/> لوحة تحكم أولية</div></div>
        <div className="notice"><ShieldAlert size={19}/><div><b>تنبيه: وضع العرض الأولي</b><p>الواجهة والكتالوج جاهزان كبنية أولية. محركات الفحص والمصادقة وقاعدة البيانات لم تُربط بعد، لذلك لن تظهر أي نتائج تشغيل وهمية.</p></div></div>
        <div className="stats">
          <Stat icon={Boxes} label="الأدوات في الكتالوج" value={tools.length.toString()} detail="تكاملات مخطط لها" tone="blue"/>
          <Stat icon={Radar} label="مهام الفحص" value="0" detail="لا توجد مهام منفذة" tone="purple"/>
          <Stat icon={ShieldCheck} label="الأصول المسجلة" value="0" detail="بانتظار إضافة نطاق مصرح" tone="green"/>
          <Stat icon={AlertTriangle} label="تنبيهات مفتوحة" value="0" detail="لا توجد بيانات SOC بعد" tone="orange"/>
        </div>
        <div className="section-head"><div><h2>كتالوج الأدوات الأمنية</h2><p>استكشف الأدوات التي سنربطها بمحركات تشغيل حقيقية على مراحل.</p></div><span className="count-pill">{filtered.length} أداة</span></div>
        <div className="filters"><div className="search"><Search size={18}/><input value={query} onChange={e=>setQuery(e.target.value)} placeholder="ابحث عن أداة أو وظيفة..."/></div><div className="category-filter"><Filter size={17}/><select value={category} onChange={e=>setCategory(e.target.value)}>{categories.map(c=><option key={c}>{c}</option>)}</select></div></div>
        <div className="tool-grid">{filtered.map(t=><article className="tool-card" key={t.name}><div className="tool-top"><div className="tool-icon"><TerminalSquare size={19}/></div><span className="planned"><span/> مخطط للربط</span></div><h3>{t.name}</h3><p>{t.description}</p><div className="tool-foot"><span>{t.category}</span><span>{t.tag}</span></div></article>)}</div>
        <footer><span>CYBER SECURITY AI AGENT</span><span><CircleCheck size={14}/> واجهة أولية — لا توجد عمليات فحص نشطة</span></footer>
      </div>
    </section>
  </main>;
}

function Stat({icon:Icon,label,value,detail,tone}:{icon:typeof Boxes;label:string;value:string;detail:string;tone:string}) {
  return <article className="stat-card"><div className={"stat-icon "+tone}><Icon size={20}/></div><div><small>{label}</small><strong>{value}</strong><p>{detail}</p></div></article>;
}
