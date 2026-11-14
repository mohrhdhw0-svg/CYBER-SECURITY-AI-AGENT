import {NextRequest,NextResponse} from "next/server";
import {setAdminSession,validSecret} from "@/app/lib/approval-store";
export const runtime="nodejs";
export async function POST(req:NextRequest){const expected=process.env.ADMIN_PANEL_PASSWORD;if(!expected||!process.env.ADMIN_SESSION_SECRET)return NextResponse.json({error:"لم يتم إعداد دخول الإدارة."},{status:503});let body:any;try{body=await req.json()}catch{return NextResponse.json({error:"طلب غير صالح."},{status:400})}if(typeof body.password!=="string"||!validSecret(body.password,expected))return NextResponse.json({error:"كلمة المرور غير صحيحة."},{status:401});await setAdminSession();return NextResponse.json({ok:true});}
