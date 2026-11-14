import {NextRequest,NextResponse} from "next/server";
import {send} from "@vercel/queue";
import {isAdmin,listRequests,getRequest,updateRequest} from "@/app/lib/approval-store";
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
  if(!process.env.ENGINE_URL||!process.env.ENGINE_API_TOKEN||!process.env.SCAN_APPROVAL_SECRET)return NextResponse.json({error:"محرك الفحص أو أسرار الموافقات غير مهيأة؛ لم يبدأ الفحص."},{status:503});
  item.status="scanning";item.expiresAt=new Date(Date.now()+24*60*60*1000).toISOString();item.authorizationReference="admin-approved:"+item.id;delete item.error;
  await updateRequest(item);
  try{
   await send("ip-scan-requests",{requestId:item.id},{idempotencyKey:item.id,retentionSeconds:86400});
  }catch{
   item.status="failed";item.error="تعذر وضع الفحص في قائمة المهام؛ تحقق من تفعيل Vercel Queues وصلاحيات OIDC.";await updateRequest(item);
   return NextResponse.json({request:item,error:item.error},{status:503});
  }
  return NextResponse.json({request:item,queued:true},{status:202});
 }catch{return NextResponse.json({error:"تعذر تحديث الطلب أو حفظه."},{status:503})}
}
