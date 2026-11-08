const FEEDS={"Feodo Tracker":"https://feodotracker.abuse.ch/downloads/ipblocklist.json","SSLBL":"https://sslbl.abuse.ch/blacklist/sslipblacklist.csv","Blocklist.de":"https://lists.blocklist.de/lists/all.txt"};
const validIP=s=>/^(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)$/.test(s||"");
function parse(source,text){const out=[];if(source==="Feodo Tracker"){let data;try{data=JSON.parse(text)}catch{return out}for(const row of Array.isArray(data)?data:[]){const ip=row.ip_address||row.ip||row.dst_ip;if(validIP(ip))out.push({ip,source,type:"Botnet C2",first_seen:row.first_seen||row.firstseen||row.date_added||null})}return out}for(const line of text.split(/\r?\n/)){const t=line.trim();if(!t||t.startsWith("#"))continue;if(source==="Blocklist.de"){if(validIP(t))out.push({ip:t,source,type:"Reported hostile IP",first_seen:null});continue}const cols=t.split(",").map(v=>v.trim().replace(/^["']|["']$/g,""));const ip=cols.find(validIP);if(ip)out.push({ip,source,type:"Malicious SSL",first_seen:cols.find(v=>/^20\d{2}-\d{2}-\d{2}/.test(v))||null})}return out}
async function locateBatch(ips){
 if(!ips.length)return{results:[],diagnostics:["No IPs to locate"]};
 try{
  const r=await fetch("https://hackmyip.com/api/bulk",{method:"POST",headers:{"Content-Type":"application/json","Accept":"application/json"},body:JSON.stringify({ips}),cf:{cacheTtl:3600}});
  const raw=await r.text();
  if(!r.ok)return{results:[],diagnostics:["hackmyip.com: HTTP "+r.status+" "+raw.slice(0,180)]};
  const d=JSON.parse(raw);const rows=d?.data?.results||d?.results||[];
  const results=rows.filter(x=>x&&x.ip&&Number.isFinite(Number(x.lat))&&Number.isFinite(Number(x.lon))).map(x=>({ip:x.ip,country:x.country||null,country_code:x.country_code||x.countryCode||null,lat:Number(x.lat),lon:Number(x.lon),geo_source:"hackmyip.com"}));
  return{results,diagnostics:["hackmyip.com: returned "+rows.length+" rows; coordinates "+results.length]};
 }catch(e){return{results:[],diagnostics:["hackmyip.com: "+String(e.message||e).slice(0,180)]}}
}
export async function onRequestGet(){
 const results=await Promise.all(Object.entries(FEEDS).map(async([source,url])=>{try{const r=await fetch(url,{headers:{"User-Agent":"ThreatAtlas-Defensive-Research/1.0","Accept":"application/json,text/plain"},cf:{cacheTtl:240}});if(!r.ok)throw Error("HTTP "+r.status);const text=await r.text();if(source==="SSLBL"&&/deprecated/i.test(text))return{source,status:"DEPRECATED",items:[],error:"Feed retired by provider"};return{source,status:"ONLINE",items:parse(source,text).slice(0,100)}}catch(e){return{source,status:"ERROR",items:[],error:String(e.message||e)}}}));
 const unique=new Map();for(const r of results)for(const x of r.items)if(!unique.has(x.ip))unique.set(x.ip,x);
 const indicators=[...unique.values()].slice(0,120);
 const sample=indicators.map(x=>x.ip);
 const geoResults=[];const geoDiagnostics=[];
 for(let i=0;i<sample.length;i+=50){
  const batch=await locateBatch(sample.slice(i,i+50));
  geoResults.push(...batch.results);geoDiagnostics.push(...batch.diagnostics);
 }
 const geo={results:geoResults,diagnostics:geoDiagnostics};
 const byIP=new Map(geo.results.map(x=>[x.ip,x]));
 const enriched=indicators.map(x=>{const g=byIP.get(x.ip);return{...x,country:g?.country||null,country_code:g?.country_code||null,lat:g?.lat??null,lon:g?.lon??null,geo_source:g?.geo_source||null}});
 const active=results.filter(x=>x.status==="ONLINE").length;
 return Response.json({status:active===2?"online":active===1?"partial":"offline",generated_at:new Date().toISOString(),indicators:enriched,geolocation:{attempted:sample.length,located:geo.results.length,providers:["hackmyip.com bulk"],diagnostics:geo.diagnostics},sources:Object.fromEntries(results.map(x=>[x.source,{status:x.status,count:x.items.length,error:x.error||null}]))},{headers:{"Cache-Control":"no-store"}});
}