const FEEDS={"Feodo Tracker":"https://feodotracker.abuse.ch/downloads/ipblocklist.json","SSLBL":"https://sslbl.abuse.ch/blacklist/sslipblacklist.csv","Blocklist.de":"https://lists.blocklist.de/lists/all.txt"};
const validIP=s=>/^(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)$/.test(s||"");
function parse(source,text){const out=[];if(source==="Feodo Tracker"){let data;try{data=JSON.parse(text)}catch{return out}for(const row of Array.isArray(data)?data:[]){const ip=row.ip_address||row.ip||row.dst_ip;if(validIP(ip))out.push({ip,source,type:"Botnet C2",first_seen:row.first_seen||row.firstseen||row.date_added||null})}return out}for(const line of text.split(/\r?\n/)){const t=line.trim();if(!t||t.startsWith("#"))continue;if(source==="Blocklist.de"){if(validIP(t))out.push({ip:t,source,type:"Reported hostile IP",first_seen:null});continue}const cols=t.split(",").map(v=>v.trim().replace(/^["']|["']$/g,""));const ip=cols.find(validIP);if(ip)out.push({ip,source,type:"Malicious SSL",first_seen:cols.find(v=>/^20\d{2}-\d{2}-\d{2}/.test(v))||null})}return out}
async function locate(ip){
 const diagnostics=[];
 const attempts=[
  ["freeipapi.com","https://free.freeipapi.com/api/v1/json/"+encodeURIComponent(ip),async d=>({country:d.countryName||null,country_code:d.countryCode||null,lat:d.latitude,lon:d.longitude})],
  ["ipapi.co","https://ipapi.co/"+encodeURIComponent(ip)+"/json/",async d=>({country:d.country_name||d.country||null,country_code:d.country_code||null,lat:d.latitude,lon:d.longitude})],
  ["ipwho.is","https://ipwho.is/"+encodeURIComponent(ip),async d=>d.success?({country:d.country||null,country_code:d.country_code||null,lat:d.latitude,lon:d.longitude}):null]
 ];
 for(const [name,url,extract] of attempts){
  try{
   const r=await fetch(url,{headers:{"User-Agent":"ThreatAtlas/1.0","Accept":"application/json"},cf:{cacheTtl:3600}});
   const raw=await r.text();
   if(!r.ok){diagnostics.push(name+": HTTP "+r.status+" "+raw.slice(0,100));continue}
   let d;try{d=JSON.parse(raw)}catch{diagnostics.push(name+": response not JSON");continue}
   const g=await extract(d);
   if(g&&g.lat!=null&&g.lon!=null&&Number.isFinite(Number(g.lat))&&Number.isFinite(Number(g.lon)))return{result:{ip,country:g.country,country_code:g.country_code,lat:Number(g.lat),lon:Number(g.lon),geo_source:name},diagnostics};
   diagnostics.push(name+": no coordinates "+JSON.stringify(d).slice(0,120));
  }catch(e){diagnostics.push(name+": "+String(e.message||e).slice(0,120))}
 }
 return{result:null,diagnostics};
}
export async function onRequestGet(){
 const results=await Promise.all(Object.entries(FEEDS).map(async([source,url])=>{try{const r=await fetch(url,{headers:{"User-Agent":"ThreatAtlas-Defensive-Research/1.0","Accept":"application/json,text/plain"},cf:{cacheTtl:240}});if(!r.ok)throw Error("HTTP "+r.status);const text=await r.text();if(source==="SSLBL"&&/deprecated/i.test(text))return{source,status:"DEPRECATED",items:[],error:"Feed retired by provider"};return{source,status:"ONLINE",items:parse(source,text).slice(0,100)}}catch(e){return{source,status:"ERROR",items:[],error:String(e.message||e)}}}));
 const unique=new Map();for(const r of results)for(const x of r.items)if(!unique.has(x.ip))unique.set(x.ip,x);
 const indicators=[...unique.values()].slice(0,120);
 const geoResults=await Promise.all(indicators.slice(0,24).map(x=>locate(x.ip)));
 const byIP=new Map(geoResults.filter(x=>x.result).map(x=>[x.result.ip,x.result]));
 const enriched=indicators.map(x=>{const g=byIP.get(x.ip);return{...x,country:g?.country||null,country_code:g?.country_code||null,lat:g?.lat??null,lon:g?.lon??null,geo_source:g?.geo_source||null}});
 const active=results.filter(x=>x.status==="ONLINE").length;
 return Response.json({status:active===2?"online":active===1?"partial":"offline",generated_at:new Date().toISOString(),indicators:enriched,geolocation:{attempted:Math.min(indicators.length,24),located:byIP.size,providers:["freeipapi.com","ipapi.co","ipwho.is"],sample_ip:indicators[0]?.ip||null,diagnostics:geoResults[0]?.diagnostics||[]},sources:Object.fromEntries(results.map(x=>[x.source,{status:x.status,count:x.items.length,error:x.error||null}]))},{headers:{"Cache-Control":"no-store"}});
}