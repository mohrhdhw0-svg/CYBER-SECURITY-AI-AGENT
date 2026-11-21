import { createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import { isIPv4 } from "node:net";
import { cookies } from "next/headers";
const redisUrl=()=>process.env.UPSTASH_REDIS_REST_URL?.replace(/\/$/,"");
const redisToken=()=>process.env.UPSTASH_REDIS_REST_TOKEN;
export type ScanRequest={id:string;ip:string;status:"pending"|"approved"|"rejected"|"scanning"|"completed"|"failed";createdAt:string;expiresAt?:string;decisionAt?:string;authorizationReference?:string;ticketProof?:string;result?:unknown;error?:string};
async function redis(command:string[]){
 const rawUrl=redisUrl(),token=redisToken();
 if(!rawUrl||!token)throw new Error("Approval storage is not configured.");
 let endpoint:URL;
 try{endpoint=new URL(rawUrl)}catch{throw new Error("Approval storage URL is invalid.");}
 const localHost=["localhost","127.0.0.1","[::1]"].includes(endpoint.hostname);
 const localHttp=process.env.NODE_ENV!=="production"&&endpoint.protocol==="http:"&&localHost;
 if(endpoint.username||endpoint.password||endpoint.search||endpoint.hash||(endpoint.protocol!=="https:"&&!localHttp)){
  throw new Error("Approval storage must use a valid HTTPS URL.");
 }
 const response=await fetch(endpoint,{
  method:"POST",
  headers:{Authorization:`Bearer ${token}`,"Content-Type":"application/json"},
  body:JSON.stringify(command),
  cache:"no-store",
  redirect:"error",
  signal:AbortSignal.timeout(4_000),
 });
 if(!response.ok){await response.body?.cancel().catch(()=>{});throw new Error("Approval storage request failed.");}
 const declaredLength=Number(response.headers.get("content-length")||0);
 if(Number.isFinite(declaredLength)&&declaredLength>16_384){
  await response.body?.cancel().catch(()=>{});
  throw new Error("Approval storage response is too large.");
 }
 if(!response.body)throw new Error("Approval storage returned an empty response.");
 const reader=response.body.getReader();
 const decoder=new TextDecoder("utf-8",{fatal:true});
 let total=0,text="";
 try{
  while(true){
   const {done,value}=await reader.read();
   if(done)break;
   total+=value.byteLength;
   if(total>16_384){await reader.cancel();throw new Error("Approval storage response is too large.");}
   text+=decoder.decode(value,{stream:true});
  }
  text+=decoder.decode();
 }finally{reader.releaseLock();}
 let data:any;
 try{data=JSON.parse(text)}catch{throw new Error("Approval storage returned invalid JSON.");}
 if(data?.error)throw new Error("Approval storage error.");
 return data?.result;
}
export async function saveRequest(item:ScanRequest){await redis(["SET",`scan:req:${item.id}`,JSON.stringify(item),"EX","604800"]);await redis(["LPUSH","scan:req:index",item.id]);await redis(["LTRIM","scan:req:index","0","499"]);}
export async function getRequest(id:string):Promise<ScanRequest|null>{const v=await redis(["GET",`scan:req:${id}`]);return v?JSON.parse(v):null;}
export type AdminScanRequest = Pick<ScanRequest, "id" | "ip" | "status" | "createdAt" | "expiresAt">;
export async function listRequests():Promise<AdminScanRequest[]>{
 const ids=await redis(["LRANGE","scan:req:index","0","199"]) as string[];
 if(!Array.isArray(ids))throw new Error("Approval request index is invalid.");
 const rows=await Promise.all([...new Set(ids)].filter((id):id is string=>typeof id==="string"&&/^[a-f0-9]{36}$/.test(id)).map(getRequest));
 return rows.filter((x):x is ScanRequest=>!!x).map(({id,ip,status,createdAt,expiresAt})=>({id,ip,status,createdAt,expiresAt}));
}
export async function updateRequest(item:ScanRequest){await redis(["SET",`scan:req:${item.id}`,JSON.stringify(item),"EX","604800"]);}
const sign=(value:string,secret:string)=>createHmac("sha256",secret).update(value).digest("base64url");
export function validSecret(value:string,expected:string){const a=Buffer.from(value),b=Buffer.from(expected);return a.length===b.length&&timingSafeEqual(a,b);}
export async function setAdminSession(){const secret=process.env.ADMIN_SESSION_SECRET;if(!secret)throw new Error("Admin session secret missing");const payload=Buffer.from(JSON.stringify({exp:Date.now()+8*60*60*1000})).toString("base64url");const value=payload+"."+sign(payload,secret);(await cookies()).set("cyber_admin",value,{httpOnly:true,secure:process.env.NODE_ENV==="production",sameSite:"strict",path:"/",maxAge:8*60*60});}
export async function isAdmin(){const secret=process.env.ADMIN_SESSION_SECRET;if(!secret)return false;const value=(await cookies()).get("cyber_admin")?.value||"";const parts=value.split(".");if(parts.length!==2)return false;const [payload,sig]=parts;if(!/^[A-Za-z0-9_-]+$/.test(payload)||!/^[A-Za-z0-9_-]{43}$/.test(sig)||!validSecret(sig,sign(payload,secret)))return false;try{const claims=JSON.parse(Buffer.from(payload,"base64url").toString());return !!claims&&typeof claims.exp==="number"&&Number.isSafeInteger(claims.exp)&&claims.exp>Date.now();}catch{return false;}}
export function createScanPermit(ip:string,id:string,expiresAt:string){const secret=process.env.SCAN_APPROVAL_SECRET;if(!secret)throw new Error("Scan permit secret missing");const exp=Date.parse(expiresAt);if(!isIPv4(ip)||!/^([a-f0-9]{36})$/.test(id)||!Number.isSafeInteger(exp)||exp<=Date.now())throw new Error("Scan permit claims are invalid.");const payload=Buffer.from(JSON.stringify({ip,id,exp})).toString("base64url");return payload+"."+sign(payload,secret);}
export function newId(){return randomBytes(18).toString("hex");}

export async function checkLoginRateLimit(clientKey:string){
 const key="admin:login:"+createHmac("sha256",process.env.ADMIN_SESSION_SECRET||"").update(clientKey).digest("hex");
 const count=await redis(["EVAL","local count=redis.call('INCR', KEYS[1]); if count == 1 then redis.call('EXPIRE', KEYS[1], ARGV[1]); end; return count","1",key,"900"]);
 if(!Number.isSafeInteger(count)||count<1)throw new Error("Login rate-limit counter is invalid.");
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
