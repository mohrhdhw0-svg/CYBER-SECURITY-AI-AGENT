import { createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import { cookies } from "next/headers";
const redisUrl=()=>process.env.UPSTASH_REDIS_REST_URL?.replace(/\/$/,"");
const redisToken=()=>process.env.UPSTASH_REDIS_REST_TOKEN;
export type ScanRequest={id:string;ip:string;status:"pending"|"approved"|"rejected"|"scanning"|"completed"|"failed";createdAt:string;expiresAt?:string;decisionAt?:string;authorizationReference?:string;ticketProof?:string;result?:unknown;error?:string};
async function redis(command:string[]){const url=redisUrl(),token=redisToken();if(!url||!token)throw new Error("Approval storage is not configured.");const r=await fetch(url,{method:"POST",headers:{Authorization:`Bearer ${token}`,"Content-Type":"application/json"},body:JSON.stringify(command),cache:"no-store"});if(!r.ok)throw new Error("Approval storage request failed.");const data=await r.json();if(data.error)throw new Error("Approval storage error.");return data.result;}
export async function saveRequest(item:ScanRequest){await redis(["SET",`scan:req:${item.id}`,JSON.stringify(item),"EX","604800"]);await redis(["LPUSH","scan:req:index",item.id]);await redis(["LTRIM","scan:req:index","0","499"]);}
export async function getRequest(id:string):Promise<ScanRequest|null>{const v=await redis(["GET",`scan:req:${id}`]);return v?JSON.parse(v):null;}
export async function listRequests():Promise<ScanRequest[]>{const ids=await redis(["LRANGE","scan:req:index","0","499"]) as string[];const rows=await Promise.all([...new Set(ids)].map(getRequest));return rows.filter((x):x is ScanRequest=>!!x);}
export async function updateRequest(item:ScanRequest){await redis(["SET",`scan:req:${item.id}`,JSON.stringify(item),"EX","604800"]);}
const sign=(value:string,secret:string)=>createHmac("sha256",secret).update(value).digest("base64url");
export function validSecret(value:string,expected:string){const a=Buffer.from(value),b=Buffer.from(expected);return a.length===b.length&&timingSafeEqual(a,b);}
export async function setAdminSession(){const secret=process.env.ADMIN_SESSION_SECRET;if(!secret)throw new Error("Admin session secret missing");const payload=Buffer.from(JSON.stringify({exp:Date.now()+8*60*60*1000})).toString("base64url");const value=payload+"."+sign(payload,secret);(await cookies()).set("cyber_admin",value,{httpOnly:true,secure:process.env.NODE_ENV==="production",sameSite:"strict",path:"/",maxAge:8*60*60});}
export async function isAdmin(){const secret=process.env.ADMIN_SESSION_SECRET;if(!secret)return false;const value=(await cookies()).get("cyber_admin")?.value||"";const [payload,sig]=value.split(".");if(!payload||!sig||!validSecret(sig,sign(payload,secret)))return false;try{return JSON.parse(Buffer.from(payload,"base64url").toString()).exp>Date.now();}catch{return false;}}
export function createScanPermit(ip:string,id:string,expiresAt:string){const secret=process.env.SCAN_APPROVAL_SECRET;if(!secret)throw new Error("Scan permit secret missing");const payload=Buffer.from(JSON.stringify({ip,id,exp:Date.parse(expiresAt)})).toString("base64url");return payload+"."+sign(payload,secret);}
export function newId(){return randomBytes(18).toString("hex");}

export async function checkLoginRateLimit(clientKey:string){
 const key="admin:login:"+createHmac("sha256",process.env.ADMIN_SESSION_SECRET||"").update(clientKey).digest("hex");
 const count=Number(await redis(["INCR",key]));
 if(count===1)await redis(["EXPIRE",key,"900"]);
 return {allowed:count<=5,remaining:Math.max(0,5-count)};
}
export async function clearLoginRateLimit(clientKey:string){
 const key="admin:login:"+createHmac("sha256",process.env.ADMIN_SESSION_SECRET||"").update(clientKey).digest("hex");
 await redis(["DEL",key]);
}

export async function claimScanLease(id:string,token:string){
 return await redis(["SET",`scan:lease:${id}`,token,"NX","EX","240"])==="OK";
}
export async function releaseScanLease(id:string,token:string){
 await redis(["EVAL","if redis.call('GET', KEYS[1]) == ARGV[1] then return redis.call('DEL', KEYS[1]) else return 0 end","1",`scan:lease:${id}`,token]);
}

/** Atomically move a pending request to scanning/rejected so concurrent admin actions cannot both win. */
export async function transitionPendingRequest(item:ScanRequest){
 const result=await redis(["EVAL",
  "local raw=redis.call('GET', KEYS[1]); if not raw then return 0 end; local current=cjson.decode(raw); if current.status ~= 'pending' then return 0 end; redis.call('SET', KEYS[1], ARGV[1], 'EX', '604800'); return 1",
  "1",`scan:req:${item.id}`,JSON.stringify(item)]);
 return Number(result)===1;
}
