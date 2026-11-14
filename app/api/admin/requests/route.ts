import {NextRequest,NextResponse} from "next/server";
import {isAdmin,listRequests,getRequest,updateRequest,createScanPermit} from "@/app/lib/approval-store";
export const runtime="nodejs";
export const dynamic="force-dynamic";
export async function GET(){if(!await isAdmin())return NextResponse.json({error:"غير مصرح."},{status:401});try{return NextResponse.json({requests:await listRequests()})}catch{return NextResponse.json({error:"مخزن الموافقات غير مهيأ أو غير متاح."},{status:503})}}
export async function POST(req:NextRequest){
 if(!await isAdmin())return NextResponse.json({error:"غير مصرح."},{status:401});
 let b:any;try{b=await req.json()}catch{return NextResponse.json({error:"طلب غير صالح."},{status:400})}
 if(typeof b.id!=="string"||!["approve","reject"].includes(b.action))return NextResponse.json({error:"بيانات القرار غير صالحة."},{status:400});
 try{
  const item=await getRequest(b.id);if(!item)return NextResponse.json({error:"الطلب غير موجود."},{status:404});
  if(item.status!=="pending")return NextResponse.json({error:"تم اتخاذ قرار لهذا الطلب مسبقاً."},{status:409});
  item.decisionAt=new Date().toISOString();
  if(b.action==="reject"){item.status="rejected";await updateRequest(item);return NextResponse.json({request:item});}
  const base=process.env.ENGINE_URL?.replace(/\/$/,""),token=process.env.ENGINE_API_TOKEN;
  if(!base||!token||!process.env.SCAN_APPROVAL_SECRET)return NextResponse.json({error:"محرك الفحص أو سر الموافقات غير مهيأ؛ لم يبدأ الفحص."},{status:503});
  item.status="scanning";item.expiresAt=new Date(Date.now()+24*60*60*1000).toISOString();item.authorizationReference="admin-approved:"+item.id;await updateRequest(item);
  try{
   const permit=createScanPermit(item.ip,item.id,item.expiresAt);
   const response=await fetch(`${base}/scans/intel`,{method:"POST",headers:{"Content-Type":"application/json",Authorization:`Bearer ${token}`,"X-Scan-Approval":permit},body:JSON.stringify({target_ip:item.ip,authorization_reference:item.authorizationReference,confirm_authorized:true,top_ports:100}),cache:"no-store",signal:AbortSignal.timeout(115000)});
   const data=await response.json().catch(()=>({error:"استجابة غير مفهومة من المحرك."}));
   if(!response.ok)throw new Error(data.detail||data.error||"فشل محرك البحث.");
   item.status="completed";item.result=data;await updateRequest(item);
  }catch(e){item.status="failed";item.error=e instanceof Error?e.message:"تعذر تشغيل الفحص.";await updateRequest(item);}
  return NextResponse.json({request:item});
 }catch{return NextResponse.json({error:"تعذر تحديث الطلب أو حفظ التقرير."},{status:503})}
}
