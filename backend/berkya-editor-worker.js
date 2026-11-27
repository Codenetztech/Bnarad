// Berkya editorial publisher: password -> short-lived signed session.
// Cloudflare secrets: GITHUB_TOKEN, ADMIN_PASSWORD, SESSION_SECRET.
// Optional rate limit binding LOGIN_LIMITER (recommended).
const BUILD="2026-11-27-github-v4";
const REPO="Codenetztech/Bnarad", GH="https://api.github.com/repos/"+REPO;
const ORIGINS=new Set(["https://www.berkya.com","https://berkya.com"]);
const enc=new TextEncoder(),dec=new TextDecoder();
const hex=b=>Array.from(new Uint8Array(b),x=>x.toString(16).padStart(2,"0")).join("");
const b64=b=>btoa(String.fromCharCode(...new Uint8Array(b))).replace(/\+/g,"-").replace(/\//g,"_").replace(/=+$/,"");
const from64=s=>Uint8Array.from(atob(s.replace(/-/g,"+").replace(/_/g,"/").padEnd(Math.ceil(s.length/4)*4,"=")),x=>x.charCodeAt(0));
async function hash(s){return hex(await crypto.subtle.digest("SHA-256",enc.encode(s)))}
function eq(a,b){if(a.length!==b.length)return false;let d=0;for(let i=0;i<a.length;i++)d|=a.charCodeAt(i)^b.charCodeAt(i);return d===0}
async function sign(s,e){let k=await crypto.subtle.importKey("raw",enc.encode(e.SESSION_SECRET+"|"+await hash(e.ADMIN_PASSWORD)),{name:"HMAC",hash:"SHA-256"},false,["sign"]);return b64(await crypto.subtle.sign("HMAC",k,enc.encode(s)))}
async function mint(e){let p=b64(enc.encode(JSON.stringify({sub:"admin",exp:Math.floor(Date.now()/1000)+28800,nonce:crypto.randomUUID()})));return p+"."+await sign(p,e)}
async function verify(t,e){try{if(!t||t.length>2048)return false;let [p,s,...rest]=t.split(".");if(rest.length||!p||!s||!eq(s,await sign(p,e)))return false;let j=JSON.parse(dec.decode(from64(p)));return j.sub==="admin"&&j.exp>Math.floor(Date.now()/1000)}catch{return false}}
const allowedPath=p=>/^(news\.js|articles\.js|index\.html|berkya-layout\.json|berkya-media\.json)$/.test(p)||/^article\/[a-z0-9_-]{3,100}\.html$/.test(p)||/^assets\/(?:uploads|branding)\/[a-z0-9][a-z0-9_.-]{0,150}\.(?:jpg|jpeg|png|webp)$/i.test(p)||/^media\/[a-z0-9][a-z0-9_.-]{0,150}\.(?:jpg|jpeg|png|webp)$/i.test(p);
const sha=s=>/^[0-9a-f]{40}$/i.test(s||"");
const attempts=new Map();
function localLimit(ip){let now=Date.now(),a=attempts.get(ip);if(!a||a.until<now){a={n:0,until:now+60000};attempts.set(ip,a)}if(attempts.size>5000)for(let [k,v] of attempts){if(v.until<now)attempts.delete(k)}return ++a.n<=5}
export default {async fetch(req,env){
 const u=new URL(req.url),origin=req.headers.get("Origin"),okOrigin=ORIGINS.has(origin),cors=okOrigin?{"Access-Control-Allow-Origin":origin,"Access-Control-Allow-Methods":"GET,POST,OPTIONS","Access-Control-Allow-Headers":"authorization,content-type","Access-Control-Max-Age":"600","Vary":"Origin"}:{"Vary":"Origin"};
 const reply=(obj,status=200)=>new Response(JSON.stringify(obj),{status,headers:{...cors,"Content-Type":"application/json; charset=utf-8","Cache-Control":"no-store","X-Content-Type-Options":"nosniff"}});
 if(req.method==="OPTIONS")return okOrigin?new Response(null,{status:204,headers:cors}):reply({error:"Origin not allowed"},403);
 const ready=!!env.GITHUB_TOKEN&&!!env.ADMIN_PASSWORD&&String(env.SESSION_SECRET||"").length>=32;
 if(u.pathname==="/health"&&req.method==="GET"){let session_test=false; if(ready){try{session_test=await verify(await mint(env),env)}catch{}} return reply({service:"berkya-editor",build:BUILD,ready,session_test});}
 if(!okOrigin)return reply({error:"Origin not allowed"},403);
 if(!ready)return reply({error:"Worker secrets missing"},503);
 if(req.method!=="POST")return reply({error:"Method not allowed"},405);
 if(Number(req.headers.get("Content-Length")||0)>16*1024*1024)return reply({error:"Request too large"},413);
 let stage="request";
 try{
 if(u.pathname==="/login"){
   stage="login-rate-limit";
   let ip=req.headers.get("CF-Connecting-IP")||"unknown";
   let rate=env.LOGIN_LIMITER?await env.LOGIN_LIMITER.limit({key:ip}):{success:localLimit(ip)};
   if(!rate.success)return reply({error:"Too many login attempts. Try later."},429);
   stage="login-password-check";
   let j=await req.json();if(typeof j.password!=="string"||j.password.length>256||j.username!=="admin"||!eq(await hash(j.password),await hash(env.ADMIN_PASSWORD)))return reply({error:"Invalid username or password"},401);
   stage="login-session-signing";
   return reply({session:await mint(env),expiresIn:28800});
 }
 if(u.pathname!=="/github")return reply({error:"Not found"},404);
 stage="github-session-check";
 const session=(req.headers.get("Authorization")||"").replace(/^Bearer\s+/i,"");
 if(!await verify(session,env))return reply({error:"Login expired or invalid"},401);
 let j=await req.json(),path=j.path,method=j.method||"GET",payload=j.payload;
 if(typeof path!=="string"||path.length>300||path.includes("..")||path.includes("%")||!["GET","PUT","POST","PATCH"].includes(method))return reply({error:"Invalid API request"},400);
 let permitted=false;
 if(method==="GET"){
   permitted=path===""||path==="/git/ref/heads/main"||path==="/git/refs/heads/main"||/^\/git\/commits\/[0-9a-f]{40}$/i.test(path);
   if(path.startsWith("/contents/")){let [p,q]=path.slice(10).split("?");permitted=allowedPath(p)&&(!q||/^ref=(main|[0-9a-f]{40})$/i.test(q));}
 }
 if(method==="PUT"&&path.startsWith("/contents/"))permitted=allowedPath(path.slice(10))&&payload?.branch==="main"&&typeof payload.content==="string"&&payload.content.length<12000000;
 if(method==="POST"&&path==="/git/blobs")permitted=payload?.encoding==="base64"&&typeof payload.content==="string"&&payload.content.length<12000000;
 if(method==="POST"&&path==="/git/trees")permitted=sha(payload?.base_tree)&&Array.isArray(payload.tree)&&payload.tree.length>0&&payload.tree.length<=250&&payload.tree.every(x=>allowedPath(x.path)&&x.type==="blob"&&x.mode==="100644"&&(typeof x.content==="string"||sha(x.sha)||x.sha===null));
 if(method==="POST"&&path==="/git/commits")permitted=sha(payload?.tree)&&Array.isArray(payload.parents)&&payload.parents.length===1&&sha(payload.parents[0])&&typeof payload.message==="string";
 if(method==="PATCH"&&path==="/git/refs/heads/main")permitted=sha(payload?.sha)&&payload.force===false;
 if(!permitted)return reply({error:"Repository path or action not allowed"},403);
 stage="github-token-check";
 const token=String(env.GITHUB_TOKEN||"").trim();
 if(!/^[A-Za-z0-9_]+$/.test(token))return reply({error:"GitHub token contains invalid characters. Paste only the original token."},503);
 const headers=new Headers({"Authorization":"Bearer "+token,"Accept":j.raw?"application/vnd.github.raw+json":"application/vnd.github+json","X-GitHub-Api-Version":"2022-11-28","User-Agent":"Berkya-Editorial-Worker"});
 const init={method,headers,redirect:"manual"};
 if(method!=="GET"){headers.set("Content-Type","application/json");init.body=JSON.stringify(payload);}
 stage="github-request";
 let r=await globalThis.fetch(GH+path,init);
 if(r.status>=300&&r.status<400)return reply({error:"GitHub API redirect refused; verify the repository URL.",upstream_status:r.status},502);
 stage="github-response";
 if(!r.ok){let msg=r.status===401?"GitHub rejected the token. Check its value or expiry.":r.status===403?"GitHub denied access. Check repository Contents permissions and rate limit.":r.status===404?"GitHub repository or file not found.":r.status===429?"GitHub rate limit exceeded.":"GitHub API returned HTTP "+r.status;return reply({error:msg,upstream_status:r.status},r.status);}
 let out=await r.text();return new Response(r.status===204||r.status===205?null:out,{status:r.status,headers:{...cors,"Content-Type":j.raw?"text/plain; charset=utf-8":"application/json; charset=utf-8","Cache-Control":"no-store","X-Content-Type-Options":"nosniff"}});
 }catch(e){console.error("Berkya request failed",stage,e?.name||"Error");return reply({error:"Request failed at "+stage+" ("+(["TypeError","NetworkError","AbortError","SyntaxError","RangeError"].includes(e?.name)?e.name:"Error")+")",build:BUILD},500)}
}};
