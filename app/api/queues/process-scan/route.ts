import {handleCallback} from "@vercel/queue";
import {randomBytes} from "node:crypto";
import {claimScanLease,releaseScanLease,getRequest,updateRequest,createScanPermit} from "@/app/lib/approval-store";
export const runtime="nodejs";
export const maxDuration=180;
type ScanMessage={requestId:string};
export const POST=handleCallback(async(message:ScanMessage)=>{
 if(!message||typeof message.requestId!=="string"||!/^[a-f0-9]{36}$/.test(message.requestId))throw new Error("Invalid scan queue message.");
 const item=await getRequest(message.requestId);
 if(!item||item.status==="completed"||item.status==="rejected"||item.status==="failed")return;
 if(item.status!=="scanning")return;
 const leaseToken=randomBytes(24).toString("hex");
 if(!await claimScanLease(item.id,leaseToken))throw new Error("Scan is already being processed; retry later.");
 try{
  const current=await getRequest(item.id);
  if(!current||current.status!=="scanning")return;
  const base=process.env.ENGINE_URL?.replace(/\/$/,""),token=process.env.ENGINE_API_TOKEN;
  if(!base||!token||!current.expiresAt||!process.env.SCAN_APPROVAL_SECRET)throw new Error("Scan engine configuration is incomplete.");
  const permit=createScanPermit(current.ip,current.id,current.expiresAt);
  let response:Response;
  try{
   response=await fetch(`${base}/scans/intel`,{method:"POST",headers:{"Content-Type":"application/json",Authorization:`Bearer ${token}`,"X-Scan-Approval":permit},body:JSON.stringify({target_ip:current.ip,authorization_reference:current.authorizationReference,confirm_authorized:true,top_ports:100}),cache:"no-store",signal:AbortSignal.timeout(115000)});
  }catch(e){throw new Error(e instanceof Error?`تعذر الاتصال بمحرك الفحص مؤقتاً: ${e.message}`:"تعذر الاتصال بمحرك الفحص مؤقتاً.");}
  const data=await response.json().catch(()=>({error:"استجابة غير مفهومة من المحرك."}));
  if(!response.ok){if(response.status===408||response.status===429||response.status>=500)throw new Error(`محرك الفحص غير متاح مؤقتاً (HTTP ${response.status}).`);current.status="failed";current.error=String(data.detail||data.error||`فشل محرك الفحص (HTTP ${response.status}).`);await updateRequest(current);return;}
  current.status="completed";current.result=data;delete current.error;await updateRequest(current);
 }finally{await releaseScanLease(item.id,leaseToken);}
},{visibilityTimeoutSeconds:180,retry:(error,metadata)=>metadata.deliveryCount>8?{acknowledge:true}:{afterSeconds:Math.min(300,metadata.deliveryCount*15)}});
