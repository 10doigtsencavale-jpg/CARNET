"use strict";
// Carnet : tout le contenu est chiffré dans carnet.json. Rien de lisible n'est stocké en clair sur l'appareil.
const $=s=>document.querySelector(s),root=$("#app"),te=new TextEncoder(),td=new TextDecoder();
const esc=s=>String(s??"").replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
const b64=s=>Uint8Array.from(atob(s),c=>c.charCodeAt(0));
const norm=p=>p.normalize("NFD").replace(/[̀-ͯ]/g,"").toLowerCase().trim().split(/[^a-z]+/).filter(Boolean).join(" ");
const S=crypto.subtle;
// --- clé gardée sur l'appareil : non exportable, même par le code de l'appli ---
const idb=m=>new Promise((ok,ko)=>{const o=indexedDB.open("carnet",1);o.onupgradeneeded=()=>o.result.createObjectStore("k");o.onerror=()=>ko(o.error);o.onsuccess=()=>{const t=o.result.transaction("k",m==="r"?"readonly":"readwrite").objectStore("k");ok(t)}});
const pr=r=>new Promise((ok,ko)=>{r.onsuccess=()=>ok(r.result);r.onerror=()=>ko(r.error)});
const keyGet=async()=>{try{return await pr((await idb("r")).get("priv"))}catch(e){return null}};
const keyPut=async k=>{try{await pr((await idb("w")).put(k,"priv"))}catch(e){}};
const keyDel=async()=>{try{await pr((await idb("w")).delete("priv"))}catch(e){}};
async function privFromPhrase(file,phrase){
  const base=await S.importKey("raw",te.encode(norm(phrase)),"PBKDF2",false,["deriveKey"]);
  const k=await S.deriveKey({name:"PBKDF2",salt:b64(file.kdf.salt),iterations:file.kdf.iter,hash:"SHA-256"},base,{name:"AES-GCM",length:256},false,["decrypt"]);
  for(const sl of file.slots){try{const raw=await S.decrypt({name:"AES-GCM",iv:b64(sl.iv)},k,b64(sl.priv));
    return await S.importKey("pkcs8",raw,{name:"ECDH",namedCurve:"P-256"},false,["deriveBits"])}catch(e){}}
  return null}
const u8=b=>btoa(String.fromCharCode(...new Uint8Array(b)));
async function openEnv(env,priv){
  const eph=await S.importKey("raw",b64(env.eph),{name:"ECDH",namedCurve:"P-256"},false,[]);
  const bits=await S.deriveBits({name:"ECDH",public:eph},priv,256);
  const hk=await S.importKey("raw",bits,"HKDF",false,["deriveKey"]);
  const wk=await S.deriveKey({name:"HKDF",hash:"SHA-256",salt:new Uint8Array(0),info:te.encode("carnet-v1")},hk,{name:"AES-GCM",length:256},false,["decrypt"]);
  for(const w of env.wraps){try{const dek=await S.decrypt({name:"AES-GCM",iv:b64(w.iv)},wk,b64(w.ct));
    const dk=await S.importKey("raw",dek,"AES-GCM",false,["decrypt"]);
    return JSON.parse(td.decode(await S.decrypt({name:"AES-GCM",iv:b64(env.iv)},dk,b64(env.ct))))}catch(e){}}
  return null}
const openData=(file,priv)=>openEnv(file.data,priv);
// Chiffre pour une liste de clés publiques. Sert au budget, écrit depuis les téléphones.
async function sealEnv(obj,pubs){
  let t=JSON.stringify(obj);t+=" ".repeat(4096-t.length%4096);
  const dek=crypto.getRandomValues(new Uint8Array(32)),iv=crypto.getRandomValues(new Uint8Array(12));
  const dk=await S.importKey("raw",dek,"AES-GCM",false,["encrypt"]);
  const ct=await S.encrypt({name:"AES-GCM",iv},dk,te.encode(t));
  const eph=await S.generateKey({name:"ECDH",namedCurve:"P-256"},false,["deriveBits"]),wraps=[];
  for(const p of pubs){const pk=await S.importKey("raw",b64(p),{name:"ECDH",namedCurve:"P-256"},false,[]);
    const bits=await S.deriveBits({name:"ECDH",public:pk},eph.privateKey,256);
    const hk=await S.importKey("raw",bits,"HKDF",false,["deriveKey"]);
    const wk=await S.deriveKey({name:"HKDF",hash:"SHA-256",salt:new Uint8Array(0),info:te.encode("carnet-v1")},hk,{name:"AES-GCM",length:256},false,["encrypt"]);
    const i=crypto.getRandomValues(new Uint8Array(12));wraps.push({iv:u8(i),ct:u8(await S.encrypt({name:"AES-GCM",iv:i},wk,dek))})}
  return{eph:u8(await S.exportKey("raw",eph.publicKey)),wraps,iv:u8(iv),ct:u8(ct)}}
// --- temps ---
const nowD=()=>window.__NOW?new Date(window.__NOW):new Date();
const fmt=(d,tz,o)=>new Intl.DateTimeFormat("fr-FR",{timeZone:tz,...o}).format(d);
const hm=(d,tz)=>fmt(d,tz,{hour:"2-digit",minute:"2-digit"});
const day=(d,tz)=>fmt(d,tz,{weekday:"long",day:"numeric",month:"long"});
const TZ={MRS:"Europe/Paris",IST:"Europe/Istanbul",TPE:"Asia/Taipei"};
const dur=m=>Math.floor(m/60)+" h "+String(m%60).padStart(2,"0");
function status(D){const n=nowD(),L=D.vols.map(v=>({...v,d:new Date(v.dep),a:new Date(v.arr)})),[a1,a2,r1,r2]=L;
  const fin=x=>hm(x.a,TZ[x.to]);
  if(n<a1.d){const j=Math.ceil((a1.d-n)/864e5);return{eb:"Avant le départ",t:j<=1?"Départ dans moins de 24 h":`Départ dans ${j} jours`,s:`${a1.vol}. Marseille, ${day(a1.d,TZ.MRS)}, ${hm(a1.d,TZ.MRS)}.`}}
  for(const v of L)if(n>=v.d&&n<v.a)return{eb:"En vol",t:`${v.fromN} → ${v.toN}`,s:`${v.vol}. Arrivée à ${fin(v)}, heure locale. Soit ${hm(v.a,TZ.MRS)} en France.`};
  if(n>=a1.a&&n<a2.d)return{eb:"Escale",t:"À Istanbul",s:`${a2.vol} à ${hm(a2.d,TZ.IST)}, heure d'Istanbul.`};
  if(n>=a2.a&&n<r1.d){const j=Math.ceil((r1.d-n)/864e5);return{eb:"Sur place",t:"À Taïwan",s:`Retour dans ${j} jour${j>1?"s":""}. ${r1.vol} ${day(r1.d,TZ.TPE)}, ${hm(r1.d,TZ.TPE)}.`}}
  if(n>=r1.a&&n<r2.d)return{eb:"Escale retour",t:"À Istanbul",s:`${r2.vol} à ${hm(r2.d,TZ.IST)}. Marseille à ${fin(r2)}.`};
  return{eb:"Voyage terminé",t:"De retour en France",s:`Arrivée à Marseille ${day(r2.a,TZ.MRS)}, ${hm(r2.a,TZ.MRS)}.`}}
// --- écrans ---
const I={now:'<circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/>',vol:'<path d="M21 3 3 10l7 3 3 7z"/><path d="m10 13 5-5"/>',sej:'<path d="M3 11 12 4l9 7"/><path d="M5 10v10h14V10"/><path d="M10 20v-6h4v6"/>',bud:'<rect x="3" y="6" width="18" height="13" rx="2"/><path d="M3 10h18"/><path d="M16 15h2"/>',todo:'<rect x="4" y="4" width="16" height="16" rx="3"/><path d="m8 12 3 3 5-6"/>',urg:'<path d="M5 4h4l2 5-3 2a12 12 0 0 0 5 5l2-3 5 2v4a2 2 0 0 1-2 2A16 16 0 0 1 3 6a2 2 0 0 1 2-2z"/>'};
I.voy='<path d="M9 4 3 6v14l6-2 6 2 6-2V4l-6 2z"/><path d="M9 4v14M15 6v14"/>';I.res='<path d="M3 8a2 2 0 0 0 2-2h14a2 2 0 0 0 2 2v2a2 2 0 0 0 0 4v2a2 2 0 0 0-2 2H5a2 2 0 0 0-2-2v-2a2 2 0 0 0 0-4z"/><path d="M14 6v12"/>';
const TABS0=[["now","Maintenant"],["vol","Vols"],["sej","Planning"],["urg","Urgences"]];
const TABS=()=>VY?[["voy","Voyage"],["res","Réserv."],["vol","Vols"]].concat(B?[["todo","To Do"],["bud","Budget"]]:[],[["urg","Urgences"]]):(B?TABS0.slice(0,3).concat([["todo","To Do"],["bud","Budget"]],TABS0.slice(3)):TABS0);
let D,tab="now",up="",tick,B=null,ME=null,VY=null,VF=null;
function legCard(v){const d=new Date(v.dep),a=new Date(v.arr),tf=TZ[v.from],tt=TZ[v.to];
  return `<article class="card leg"><div class="top"><span class="fl">${esc(v.vol)}</span><span class="tag ${v.sens==="Aller"?"":"b"}">${esc(v.sens)}</span></div>
  <div class="tl"><b>${hm(d,tf)}</b><span>${esc(v.fromN)} (${esc(v.from)})</span><span class="d">${day(d,tf)}</span><b>${hm(a,tt)}</b><span>${esc(v.toN)} (${esc(v.to)})</span><span class="d">${day(a,tt)}</span></div>
  <p class="small muted">${dur(v.min)} de vol. ${esc(v.avion)}. Heures locales.</p>
  <div class="seats">${v.sieges.map(s=>`<span>${esc(s[0])} <b>${esc(s[1])}</b></span>`).join("")}</div></article>`}
function secret(id,label,val){return `<div class="kv"><span>${esc(label)}<br><b data-sec="${esc(val)}" id="${id}">••••••</b></span><button class="sm" data-show="${id}">Afficher</button></div>`}
const key=(d,tz)=>fmt(d,tz,{year:"numeric",month:"2-digit",day:"2-digit"}).split("/").reverse().join("-");
function planning(D){const M={},add=(k,x)=>(M[k]=M[k]||[]).push(x);
  D.vols.forEach(v=>{const d=new Date(v.dep),a=new Date(v.arr);add(key(d,TZ[v.from]),{h:hm(d,TZ[v.from]),t:`Décollage ${/^[AEIOU]/.test(v.fromN)?"d'":"de "}${v.fromN}`,n:v.vol});add(key(a,TZ[v.to]),{h:hm(a,TZ[v.to]),t:`Arrivée à ${v.toN}`,n:v.vol})});
  (D.etapes||[]).forEach(e=>{const un=864e5;for(let t=Date.parse(e.du+"T12:00:00Z"),f=Date.parse((e.au||e.du)+"T12:00:00Z");t<=f;t+=un)add(new Date(t).toISOString().slice(0,10),{h:e.h,t:e.titre,n:e.texte})});
  Object.values(M).forEach(l=>l.sort((x,y)=>(x.h||"").localeCompare(y.h||"")));
  const lab=k=>fmt(new Date(k+"T12:00:00Z"),"UTC",{weekday:"long",day:"numeric",month:"long"});
  const K=[...new Set(D.vols.flatMap(v=>[key(new Date(v.dep),TZ[v.from]),key(new Date(v.arr),TZ[v.to])]))].sort(),out=[];let vide=null;
  for(let t=Date.parse(K[0]+"T12:00:00Z"),f=Date.parse(K[K.length-1]+"T12:00:00Z");t<=f;t+=864e5){const k=new Date(t).toISOString().slice(0,10);
    if(M[k]){vide=null;out.push({k,label:lab(k),it:M[k]})}else if(vide){vide.label=vide.d+" au "+lab(k)}else{vide={vide:true,d:lab(k),label:lab(k)};out.push(vide)}}
  return out}
// --- voyage : programme et réservations, chiffrés pour les 4 (voyage.json + état partagé) ---
const U={et:null,pt:"prog",view:"list",rx:null};
let ES={prog:{},resa:{}},eSyncing=false,eAgain=false;
const NC={1:["#FFF1B3","#4A3B00"],2:["#FFD9AE","#5C3000"],3:["#FAD0DA","#6B1F38"],4:["#F5B5AC","#6B160E"]},nc=n=>NC[Math.min(Math.max(n,1),4)];
const MODE={car:["#E6D3BE","#5A3A1E","Voiture"],boat:["#CDE8F7","#17506E","Bateau"],plane:["#1F3A6B","#FFFFFF","Avion"],scooter:["#E3E5E8","#333C47","Scooter"],train:["#E3E5E8","#333C47","Train"],permit:["#EDE6F7","#43296B","Permis"]};
const MI={car:'<path d="M3 16v-3l2.5-5h13l2.5 5v3z"/><circle cx="7.5" cy="17.5" r="1.8"/><circle cx="16.5" cy="17.5" r="1.8"/>',boat:'<path d="M3 15h18l-2.5 4.5h-13z"/><path d="M12 3v12"/><path d="M12 4l6 8h-6"/>',scooter:'<circle cx="6" cy="17" r="2.5"/><circle cx="18" cy="17" r="2.5"/><path d="M8.5 17h7"/><path d="M15.5 17l-2.5-10h3"/><path d="M5 14l3-3h5"/>',plane:'<path d="M2.5 13.5l19-6.5-4 12-4.5-4.5-3.5 3.5v-5z"/>',train:'<rect x="6" y="3" width="12" height="13" rx="3"/><path d="M6 10h12"/><path d="M9 20l-2 2"/><path d="M15 20l2 2"/>',permit:'<rect x="5" y="3" width="14" height="18" rx="2"/><path d="M9 8h6M9 12h6M9 16h3"/>'};
const mic=(m,s=16)=>`<svg class="mi" width="${s}" height="${s}" viewBox="0 0 24 24" aria-hidden="true">${MI[m]||""}</svg>`;
const DD=s=>new Date(s+"T12:00:00Z"),ds=d=>d.toISOString().slice(0,10),addD=(s,n)=>ds(new Date(DD(s).getTime()+n*864e5));
const fd=(s,o)=>fmt(DD(s),"UTC",o),dLong=s=>fd(s,{weekday:"short",day:"numeric",month:"short"}),dShort=s=>fd(s,{day:"numeric",month:"short"});
const nw=n=>n>1?"nuits":"nuit",shortN=n=>n==="Xiaoliuqiu"?"Liuqiu":n;
const etDates=e=>{const f=addD(e.du,e.nuits-1),m1=fd(e.du,{month:"short"}),m2=fd(f,{month:"short"});return e.nuits===1?dShort(e.du):(m1===m2?fd(e.du,{day:"numeric"}).replace(/^1$/,"1er")+"-"+dShort(f):dShort(e.du)+" - "+dShort(f))};
const canW=()=>!!B&&!window.__DEMO_RO;
const mergeE=(a,b)=>{const o={prog:{...(a.prog||{})},resa:{...(a.resa||{})}};for(const k of["prog","resa"])for(const[i,v]of Object.entries(b[k]||{}))if(!o[k][i]||v.maj>o[k][i].maj)o[k][i]=v;return o};
const resa=id=>{const a=(VY.resa_init||{})[id],b=ES.resa[id];return(!a?b:!b?a:(b.maj>a.maj?b:a))||{statut:"todo"}};
const isOk=id=>resa(id).statut==="ok";
async function initV(priv){VY=null;ES={prog:{},resa:{}};if(VF&&VF.data){try{VY=await openEnv(VF.data,priv)}catch(e){}}}
const EK="carnet_etat",eApi=()=>`https://api.github.com/repos/${VY.etat.repo}/contents/${VY.etat.path}`,allPubs=()=>F.slots.map(s=>s.pub);
async function eSave(dirty){try{localStorage.setItem(EK,JSON.stringify({env:await sealEnv(ES,allPubs()),dirty}))}catch(e){}}
async function eLoad(){try{const x=JSON.parse(localStorage.getItem(EK));if(x){const o=await openEnv(x.env,ME);if(o)ES=mergeE(ES,o);return!!x.dirty}}catch(e){}return false}
const eStat=t=>{const e=$("#eSt");if(e)e.textContent=t};
const eTok=()=>B?BS.cfg.token:null;
async function eSync(force){if(window.__DEMO||!VY)return;if(eSyncing){eAgain=true;return}eSyncing=true;let dirty=force||await eLoad();
  try{if(B)await loadLocal();
    for(let n=0;n<4;n++){const h={Accept:"application/vnd.github+json"},tok=eTok();if(tok)h.Authorization="Bearer "+tok;
      const r=await fetch(eApi(),{headers:h,cache:"no-store"});let sha=null;
      if(r.ok){const j=await r.json();sha=j.sha;const o=await openEnv(JSON.parse(atob(j.content.replace(/\s/g,""))),ME);if(o){dirty=dirty||JSON.stringify(mergeE(o,ES))!==JSON.stringify(o);ES=mergeE(ES,o)}}
      else if(r.status===404){dirty=dirty||Object.keys(ES.prog).length+Object.keys(ES.resa).length>0}else throw r.status;
      if(!dirty){await eSave(false);eStat("À jour.");break}
      if(!tok){await eSave(true);eStat(B?"Changements gardés sur ce téléphone. Reliez l'accès GitHub dans Budget pour les partager.":"Lecture seule.");break}
      const body={message:"maj",content:btoa(JSON.stringify(await sealEnv(ES,allPubs())))};if(sha)body.sha=sha;
      const p=await fetch(eApi(),{method:"PUT",headers:{Accept:"application/vnd.github+json",Authorization:"Bearer "+tok},body:JSON.stringify(body)});
      if(p.ok){dirty=false;await eSave(false);eStat("Partagé avec vous 4.");break}
      if(p.status===409||p.status===422)continue;
      if(p.status===401||p.status===403||p.status===404){await eSave(true);eStat("L'accès GitHub est refusé ou expiré. Changements gardés ici.");break}
      throw p.status}
  }catch(e){await eSave(dirty);eStat(dirty?"Pas de réseau. Changements gardés ici, envoi plus tard.":"Pas de réseau. Dernière version enregistrée.")}
  eSyncing=false;if(tab==="voy"||tab==="res"){const y=scrollY;render();scrollTo(0,y)}if(eAgain){eAgain=false;eSync()}}
let eOpened=false;async function etatOpen(){if(eOpened)return;eOpened=true;await eLoad();const y=scrollY;render();scrollTo(0,y);eSync()}
addEventListener("online",()=>{if(VY)eSync()});
async function ideaToggle(id){if(!canW())return;const on=!(ES.prog[id]&&ES.prog[id].on);ES.prog={...ES.prog,[id]:{on,maj:Date.now()}};await eSave(true);const y=scrollY;render();scrollTo(0,y);eSync(true)}
// calendrier
function cal(){const E=VY.etapes,w0=(()=>{const d=DD(VY.debut),k=(d.getUTCDay()+6)%7;return addD(VY.debut,-k)})(),fin=VY.fin,weeks=[];
  const today=key(nowD(),TZ.TPE),inT=s=>s>=VY.debut&&s<=fin,hol=s=>/-12-25$|-01-01$/.test(s);
  const pieces=(du,au,w)=>{const a=w,b=addD(w,6);if(au<a||du>b)return null;const s=du<a?a:du,e=au>b?b:au;return{c1:Math.round((DD(s)-DD(a))/864e5)+1,c2:Math.round((DD(e)-DD(a))/864e5)+1,l:du<a,r:au>b}};
  const bar=(p,txt,bg,fg,icon,cls="")=>`<span class="bar ${cls}" style="grid-column:${p.c1}/${p.c2+1};background:${bg};color:${fg};border-radius:${p.l&&p.r?"0":p.l?"0 5px 5px 0":p.r?"5px 0 0 5px":"5px"}">${icon?mic(icon,13):""}<span>${esc(txt)}</span></span>`;
  for(let w=w0;w<=fin;w=addD(w,7)){const days=[...Array(7)].map((_,i)=>addD(w,i));
    const L1=E.map(e=>{const p=pieces(e.du,addD(e.du,e.nuits-1),w);if(!p)return"";const n=p.c2-p.c1+1,c=nc(e.nuits);return bar(p,n>=3?shortN(e.nom)+" · "+e.nuits+" "+nw(e.nuits):n===2?shortN(e.nom)+" · "+e.nuits+" n":shortN(e.nom),c[0],c[1],"","st")}).join("")+(days.includes(fin)?bar(pieces(fin,fin,w),"Départ","#6B7470","#FFFFFF",""):"");
    const L2=VY.transports.map(t=>{const p=pieces(t.du,t.au,w);if(!p)return"";const m=MODE[t.mode];return bar(p,"",m[0],m[1],t.mode)}).join("");
    const L3=VY.evenements.map(v=>{const p=pieces(v.d,v.d,w);if(!p)return"";return v.k==="plane"?bar(p,v.t,MODE.plane[0],MODE.plane[1],"plane"):v.k==="nye"?bar(p,v.t,"#EDE6F7","#43296B","","ev nye"):bar(p,v.t,"#FFFFFF","var(--fg)","","ev")}).join("");
    weeks.push(`<div class="wk"><div class="g7">${days.map(d=>`<span class="dn${inT(d)?" in":""}${hol(d)?" hol":""}${d===today?" tod":""}">${fd(d,{day:"numeric"})}</span>`).join("")}</div>${[L1,L2,L3].filter(x=>x).map(x=>`<div class="g7 ln7">${x}</div>`).join("")}</div>`)}
  return`<section class="cal card" aria-label="Calendrier du voyage"><div class="g7 wd">${["lun.","mar.","mer.","jeu.","ven.","sam.","dim."].map(x=>`<span>${x}</span>`).join("")}</div>${weeks.join("")}</section>
  <div class="lg">${[1,2,3,4].map(n=>`<span><i style="background:${NC[n][0]}"></i>${n===4?"4 nuits et +":n+" "+nw(n)}</span>`).join("")}</div>
  <div class="lg">${["car","boat","plane","scooter","train"].map(m=>`<span class="chip" style="background:${MODE[m][0]};color:${MODE[m][1]}">${mic(m,14)}${MODE[m][2]}</span>`).join("")}</div>`}
function carte(){const E=VY.etapes,seen={},pins=[];E.forEach((e,i)=>{const k=e.pin.join();if(seen[k]){seen[k].n=Math.max(seen[k].n,e.nuits);seen[k].ok=seen[k].ok&&isOk(e.id);return}seen[k]={e,i,n:e.nuits,ok:isOk(e.id)};pins.push(seen[k])});
  const pts=[[VY.aeroport.x,VY.aeroport.y]].concat(E.map(e=>e.pin)).map(p=>p.join(",")).join(" ");
  return`<div class="mapbox"><svg viewBox="0 0 300 560" role="img" aria-label="Carte schématique de Taïwan avec les étapes numérotées"><polygon points="221.9,15.6 251.2,38.9 276.3,43.6 286.0,62.2 265.1,101.1 265.1,126.0 251.2,171.1 233.0,217.8 216.3,280.0 202.3,342.2 174.4,404.4 139.5,458.9 129.8,513.3 125.6,544.4 108.8,539.8 104.7,513.3 90.7,474.4 62.8,451.1 44.7,432.4 27.9,373.3 20.9,311.1 34.9,248.9 62.8,194.4 83.7,155.6 132.6,93.3 153.5,54.4 202.3,35.8" fill="#EFE6D2" stroke="#A9B4B0" stroke-width="2"/>
  <polyline points="${pts}" fill="none" stroke="#2B3A67" stroke-width="3" stroke-dasharray="7 6" stroke-linejoin="round"/>
  <circle cx="${VY.aeroport.x}" cy="${VY.aeroport.y}" r="5" fill="#1F3A6B"/><text x="${VY.aeroport.x-12}" y="${VY.aeroport.y-12}" text-anchor="middle" font-size="11" font-weight="700" fill="#1F3A6B">aéroport</text>
  ${pins.map(p=>{const lab=p.e.pinLabel||String(p.i+1),r=lab.length>2?16:14,c=nc(p.n);return`<g class="pin"><circle cx="${p.e.pin[0]}" cy="${p.e.pin[1]}" r="${r}" fill="${c[0]}" stroke="${p.ok?"#2F8F4E":"#8A9099"}" stroke-width="4"/><text x="${p.e.pin[0]}" y="${p.e.pin[1]+(lab.length>1?4.2:5)}" text-anchor="middle" font-size="${lab.length>1?11:14}" font-weight="700" fill="#1C2433">${esc(lab)}</text></g>`}).join("")}</svg>
  <div class="lg"><span><i class="ring"></i>À réserver</span><span><i class="ring ok"></i>Réservé</span><span>Couleur = nombre de nuits</span></div>
  <div class="pinl">${E.map((e,i)=>`<button class="sm" data-et="${esc(e.id)}">${i+1}. ${esc(e.nom)}</button>`).join("")}</div></div>`}
function etapeList(){return`<div class="stl">${VY.etapes.map((e,i)=>{const c=nc(e.nuits);return`<button class="strow" data-et="${esc(e.id)}"><span class="badge" style="background:${c[0]};color:${c[1]}">${i+1}</span><span class="nm"><b>${esc(e.nom)}</b><small>${esc(etDates(e))} ${e.modes.map(m=>mic(m,15)).join("")}</small></span><span class="rs ${isOk(e.id)?"ok":""}">${isOk(e.id)?"Réservé":"À réserver"}</span><span class="nn"><b>${e.nuits}</b><small>${nw(e.nuits)}</small></span></button>`}).join("")}</div>`}
function etape(){const E=VY.etapes,i=E.findIndex(e=>e.id===U.et),e=E[i];if(!e){U.et=null;return V.voy()}
  const r=resa(e.id),c=nc(e.nuits),added=e.idees.filter(x=>ES.prog[x.id]&&ES.prog[x.id].on),ro=!canW();
  const CAT={Sport:["#E3EEF9","#1F3F6B"],Aventure:["#FBE3D6","#7A2E0B"],Cuisine:["#FFF1C7","#5E4300"],Culture:["#EDE6F7","#43296B"],Nature:["#DDF2E3","#1E4D2E"]};
  return`<button class="lnk" data-back>← Toutes les étapes</button>
  <header class="eth"><div><span class="eb">Étape ${i+1} sur ${E.length}</span><h1>${esc(e.nom)}</h1><span>Arrivée ${esc(dLong(e.du))} · départ ${esc(dLong(addD(e.du,e.nuits)))}</span><span class="small">${e.modes.map(m=>mic(m,15)).join("")} ${esc(e.acces)}</span></div><div class="nb" style="background:${c[0]};color:${c[1]}"><b>${e.nuits}</b><span>${nw(e.nuits)}</span></div></header>
  <section class="card"><div class="kv"><span><b class="t2">Logement</b><br><span class="small">${esc(e.logement.ou)}</span></span><button class="rs btn2 ${r.statut==="ok"?"ok":""}" data-rx="${esc(e.id)}">${r.statut==="ok"?"Réservé":"À réserver"}</button></div>
  ${r.statut==="ok"?`<p class="small">${esc([r.plateforme,r.prix].filter(Boolean).join(" · "))}${r.lien?` · <a href="${esc(r.lien)}" target="_blank" rel="noopener noreferrer">Ouvrir la réservation</a>`:""}</p>`:`<p class="small muted">Idées : ${esc(e.logement.idees)}${e.logement.prix?". Prix indicatif : "+esc(e.logement.prix):""}</p>`}</section>
  <div class="tabs2" role="tablist"><button role="tab" data-pt="prog" aria-selected="${U.pt==="prog"}">Programme (${e.jours.length+added.length})</button><button role="tab" data-pt="idees" aria-selected="${U.pt==="idees"}">Idées (${e.idees.length})</button></div>
  ${U.pt==="prog"?e.jours.map(j=>`<article class="card dj"><b>${esc(dLong(j.d))}</b><span>${esc(j.t)}</span></article>`).join("")+(added.length?`<h2 class="sec">Ajouté depuis les idées</h2>${added.map(x=>`<div class="card ad"><b>${esc(x.t)}</b>${ro?"":`<button class="sm" data-idea="${esc(x.id)}">Retirer</button>`}</div>`).join("")}`:"")
  :`<p class="small muted">Nos recommandations. ${ro?"Seuls les 2 téléphones du voyage peuvent les ajouter au programme.":"Ajoutez celles qui vous tentent au programme."}</p>${e.idees.map(x=>{const on=ES.prog[x.id]&&ES.prog[x.id].on,k=CAT[x.cat]||CAT.Culture;return`<div class="card idea"><span class="it"><span><i class="cat" style="background:${k[0]};color:${k[1]}">${esc(x.cat)}</i> <b>${esc(x.t)}</b></span><small class="muted">${esc(x.n)}</small></span>${ro?(on?'<span class="rs ok">Au programme</span>':""):`<button class="tg${on?" on":""}" data-idea="${esc(x.id)}" aria-pressed="${!!on}">${on?"✓ Au programme":"Ajouter"}</button>`}</div>`}).join("")}`}
  <p class="small muted" id="eSt" style="text-align:center"></p>`}
function resaForm(id,r,isT){return`<form class="rf" data-rf="${esc(id)}" data-statut="${esc(r.statut||"todo")}" autocomplete="off">
  <div class="seg" role="group" aria-label="Statut"><button type="button" data-rstat="todo" aria-pressed="${r.statut!=="ok"}">À réserver</button><button type="button" data-rstat="ok" aria-pressed="${r.statut==="ok"}">Réservé</button></div>
  <label class="small">${isT?"Loueur ou compagnie":"Plateforme ou hôtel"}<input class="fi" name="plateforme" maxlength="80" value="${esc(r.plateforme||"")}"></label>
  <div class="two"><label class="small">Prix<input class="fi" name="prix" maxlength="40" value="${esc(r.prix||"")}"></label><label class="small">N° de réservation<input class="fi" name="code" maxlength="60" autocapitalize="off" spellcheck="false" value="${esc(r.code||"")}"></label></div>
  <label class="small">Lien<input class="fi" name="lien" maxlength="300" inputmode="url" autocapitalize="off" spellcheck="false" value="${esc(r.lien||"")}"></label>
  <label class="small">Note<input class="fi" name="note" maxlength="200" value="${esc(r.note||"")}"></label>
  <button class="btn">Enregistrer</button></form>`}
function resaRow(id,nuits,titre,sous,isT,icon){const r=resa(id),ok=r.statut==="ok",open=U.rx===id,ro=!canW();
  return`<div class="card rr${open?" open":""}" id="rx-${esc(id)}"><button class="rh" data-rx="${esc(id)}" aria-expanded="${open}"><span class="nn">${nuits?`<b>${nuits}</b><small>n.</small>`:mic(icon,20)}</span><span class="nm"><b>${esc(titre)}</b><small>${esc(sous)}</small></span><span class="rs ${ok?"ok":r.option?"opt":""}">${ok?"Réservé":"À réserver"}</span></button>
  ${open?(ok?`<div class="rd">${r.plateforme?`<div class="kv"><span>${isT?"Loueur":"Où"}</span><b>${esc(r.plateforme)}</b></div>`:""}${r.prix?`<div class="kv"><span>Prix</span><b>${esc(r.prix)}</b></div>`:""}${r.code?secret("rc-"+id,"N° de réservation",r.code):""}${r.lien?`<a class="btn alt" href="${esc(r.lien)}" target="_blank" rel="noopener noreferrer">Ouvrir la réservation</a>`:""}${r.note?`<p class="small">${esc(r.note)}</p>`:""}</div>`:"")+(ro?(ok?"":`<p class="small muted">Pas encore réservé.</p>`):resaForm(id,r,isT)):""}</div>`}
const V2={
 voy(){if(U.et)return etape();const E=VY.etapes,n=E.reduce((a,e)=>a+e.nuits,0),ok=E.filter(e=>isOk(e.id)).length,s=status(D);
  return`<span class="kick">Carnet</span><h1 class="h">Taïwan · ${esc(dShort(VY.debut))} → ${esc(dShort(VY.fin))}</h1><p class="small muted">${n} nuits · ${E.length} étapes · ${ok}/${E.length} logements réservés</p>
  <section class="now" aria-live="polite"><span class="eb">${esc(s.eb)}</span><span class="t">${esc(s.t)}</span><span class="small">${esc(s.s)}</span></section>
  ${cal()}
  <div class="tabs2" role="tablist"><button role="tab" data-view="list" aria-selected="${U.view==="list"}">Liste des étapes</button><button role="tab" data-view="map" aria-selected="${U.view==="map"}">Carte</button></div>
  ${U.view==="map"?carte():etapeList()}<p class="small muted" id="eSt" style="text-align:center"></p>`},
 res(){const E=VY.etapes,byId={};E.forEach((e,i)=>byId[e.id]={e,i});const L=VY.urgence_logements.filter(id=>byId[id]),T=VY.transports_resa,ok=L.filter(isOk).length,okT=T.filter(t=>isOk(t.id)).length;
  return`<span class="kick">Carnet</span><h1 class="h">Réservations</h1>
  <div class="two cnt"><div class="card"><span class="small muted">Logements</span><b>${ok} / ${L.length}</b><i class="pg"><i style="width:${Math.max(3,ok/L.length*100)}%"></i></i></div><div class="card"><span class="small muted">Transports</span><b>${okT} / ${T.length}</b><i class="pg"><i style="width:${Math.max(3,okT/T.length*100)}%"></i></i></div></div>
  <h2 class="sec">Logements · dans l'ordre d'urgence</h2>
  ${L.map(id=>{const e=byId[id].e;return resaRow(id,e.nuits,e.nom,etDates(e)+((VY.notes_logements||{})[id]?" · "+VY.notes_logements[id]:""),false)}).join("")}
  <h2 class="sec">Transports</h2>
  ${T.map(t=>resaRow(t.id,0,t.t,t.d+(t.option?" · facultatif":""),true,t.kind)+(U.rx===t.id&&t.n?`<p class="small muted tn">${esc(t.n)}</p>`:"")).join("")}
  <p class="small muted lockline"><svg width="16" height="16" viewBox="0 0 24 24" aria-hidden="true"><rect x="4" y="11" width="16" height="10" rx="2"/><path d="M8 11V7a4 4 0 0 1 8 0v4"/></svg>Numéros et liens chiffrés, visibles par vous 4 seulement.</p>
  <p class="small muted" id="eSt" style="text-align:center"></p>`}};
root.addEventListener("submit",async e=>{const f=e.target.closest("[data-rf]");if(!f)return;e.preventDefault();if(!canW())return;const id=f.dataset.rf,g=n=>f.elements[n].value.trim();
  let lien=g("lien");if(lien&&!/^https:\/\//i.test(lien))lien="";
  ES.resa={...ES.resa,[id]:{statut:f.dataset.statut==="ok"?"ok":"todo",plateforme:g("plateforme"),prix:g("prix"),code:g("code"),lien,note:g("note"),maj:Date.now()}};
  U.rx=null;await eSave(true);render();const x=document.getElementById("rx-"+id);if(x)x.scrollIntoView({block:"center"});eSync(true)});
const V={
 voy(){return V2.voy()},res(){return V2.res()},
 now(){const s=status(D),n=nowD(),next=D.vols.find(v=>new Date(v.dep)>n);return `<h1 class="h">${esc(D.titre)}</h1>
  <section class="now" aria-live="polite"><span class="eb">${esc(s.eb)}</span><span class="t">${esc(s.t)}</span><span>${esc(s.s)}</span></section>
  <div class="clocks"><div class="clock"><b id="cT">${hm(n,TZ.TPE)}</b><span>Taïwan</span><em id="dT">${day(n,TZ.TPE)}</em></div><div class="clock"><b id="cF">${hm(n,TZ.MRS)}</b><span>France</span><em id="dF">${day(n,TZ.MRS)}</em></div></div>
  <p class="small muted">Taïwan a 7 h d'avance sur la France en hiver.</p>
  ${next?`<h2 class="sec">Prochain vol</h2>${legCard(next)}`:""}`},
 vol(){const[a,b,c,e]=D.vols;const rs=D.reservation||{};return `<h1 class="h">Vols</h1>
  ${rs.code?`<div class="card">${secret("sC","Code de réservation "+esc(rs.cie||""),rs.code)}${(rs.billets||[]).map((x,i)=>secret("sB"+i,"Billet "+x[0],x[1])).join("")}</div>`:""}
  <div class="card"><div class="kv"><span>Soute</span><b>${esc(D.bagages.soute)}</b></div><div class="kv"><span>Cabine</span><b>${esc(D.bagages.cabine)}</b></div><p class="small muted">Cabine : ${esc(D.bagages.dim)}.</p></div>
  <h2 class="sec">Aller</h2>${legCard(a)}<p class="stop">Escale à Istanbul : ${dur((new Date(b.dep)-new Date(a.arr))/6e4)}</p>${legCard(b)}
  <h2 class="sec">Retour</h2>${legCard(c)}<p class="stop">Escale à Istanbul : ${dur((new Date(e.dep)-new Date(c.arr))/6e4)}</p>${legCard(e)}`},
 sej(){const G=planning(D),k=key(nowD(),TZ.TPE);return `<h1 class="h">Planning</h1><p class="small muted">Heures locales du lieu indiqué.</p>
  ${G.map(g=>g.vide?`<div class="empty small">${esc(g.label)} : programme à venir.</div>`:`<article class="card day ${g.k===k?"today":""}"><h2>${esc(g.label)}${g.k===k?' <span class="tag s">Aujourd\'hui</span>':""}</h2>${g.it.map(i=>`<div class="ev"><b>${esc(i.h||"")}</b><span>${esc(i.t)}${i.n?`<br><small class="muted">${esc(i.n)}</small>`:""}</span></div>`).join("")}</article>`).join("")}`},
 bud(){return `<h1 class="h">Budget</h1>
  <section class="card" aria-label="Convertir un prix"><div class="conv"><div class="cin"><input class="fi big" id="bC" inputmode="decimal" autocomplete="off" placeholder="0" aria-label="Montant en dollars taïwanais"><span>NT$</span></div><span class="eq" aria-hidden="true">=</span><div class="cin"><input class="fi big" id="bCe" inputmode="decimal" autocomplete="off" placeholder="0" aria-label="Montant en euros"><span>€</span></div></div>
  <div class="rate"><span id="bCt"></span><button type="button" class="lnk" id="bRo">Modifier le taux</button></div>
  <form id="bRf" class="ratef" hidden><input class="fi" id="bR" inputmode="decimal" autocomplete="off" aria-label="Combien de NT$ pour 1 euro"><button class="sm">Valider</button><p class="err" id="bRe" role="alert" hidden></p></form></section>
  <form id="bF" class="card" autocomplete="off"><h2 id="bT" class="sec" style="margin:0">Ajouter une dépense</h2>
  <div class="two"><input class="fi" id="bL" required maxlength="80" autocomplete="off" placeholder="Quoi ?" aria-label="Quoi"><input class="fi" id="bM" required inputmode="decimal" autocomplete="off" placeholder="Montant" aria-label="Montant"></div>
  <div class="seg" role="group" aria-label="Monnaie">${["TWD","EUR"].map(d=>`<button type="button" data-dev="${d}">${d==="TWD"?"NT$":"€"}</button>`).join("")}</div>
  <div class="seg pay" role="group" aria-label="Qui a payé">${B.membres.map((m,i)=>`<button type="button" data-pay="${i}">${esc(m.nom)}</button>`).join("")}</div>
  <div class="datel"><label class="small muted" for="bD">Date</label><input class="fi" id="bD" type="date" required></div>
  <p class="err" id="bE" role="alert" hidden></p><button class="btn" id="bS">Ajouter</button><button type="button" class="btn alt" id="bCancel" hidden>Annuler</button></form>
  <div id="bList" style="display:contents"></div><div id="bTok"></div><p class="small muted" id="bSt" style="text-align:center"></p>`},
 todo(){return `<h1 class="h">To Do</h1><p class="small muted" id="tCount"></p>
  <section class="card" id="tList" aria-label="Choses à faire"></section>
  <form id="tF" class="card" autocomplete="off"><label class="sec" for="tI" style="margin:0">Ajouter une tâche</label><input class="fi" id="tI" maxlength="80" autocomplete="off" placeholder="Quoi ?"><button class="btn">Ajouter</button></form>
  <p class="small muted" id="bSt" style="text-align:center"></p>`},
 urg(){return `<h1 class="h">Urgences</h1>
  <h2 class="sec" style="margin-top:0">Sur place, à Taïwan</h2>
  ${D.urgences.map(u=>`<div class="card"><b>${esc(u.nom)}</b>${u.note?`<span class="small muted">${esc(u.note)}</span>`:""}<div class="call"><b>${esc(u.tel)}</b><a href="tel:${esc(u.tel.replace(/[^+\d]/g,""))}">Appeler</a></div></div>`).join("")}
  <h2 class="sec">Avant de partir</h2>${D.avant.map(t=>`<div class="card"><b>${esc(t.titre)}</b><span class="small">${esc(t.texte)}</span></div>`).join("")}
  <div class="foot"><span>Mis à jour le ${esc(up)}</span><button class="btn alt" id="lockBtn">Verrouiller sur cet appareil</button></div>`}};
function render(){const T=TABS();root.innerHTML=`<main class="page">${V[tab]()}</main><nav class="nav" style="grid-template-columns:repeat(${T.length},minmax(0,1fr))" aria-label="Rubriques">${T.map(([k,l])=>`<button data-tab="${k}" ${k===tab?'aria-current="page"':""}><svg viewBox="0 0 24 24" aria-hidden="true">${I[k]}</svg>${l}</button>`).join("")}</nav>`;scrollTo(0,0);if(tab==="bud")budOpen();if(tab==="todo")todoOpen();if(tab==="voy"||tab==="res")etatOpen()}
root.addEventListener("click",async e=>{const b=e.target.closest("button");if(!b)return;
  if(b.dataset.tab){tab=b.dataset.tab;U.et=null;U.rx=null;render()}
  else if(b.dataset.et){tab="voy";U.et=b.dataset.et;U.pt="prog";render()}
  else if(b.dataset.back!==undefined){U.et=null;render()}
  else if(b.dataset.view){U.view=b.dataset.view;render()}
  else if(b.dataset.pt){U.pt=b.dataset.pt;render()}
  else if(b.dataset.idea){await ideaToggle(b.dataset.idea)}
  else if(b.dataset.rx){U.rx=U.rx===b.dataset.rx?null:b.dataset.rx;if(tab!=="res"){tab="res";U.et=null}render();const x=document.getElementById("rx-"+U.rx);if(x)x.scrollIntoView({block:"start"})}
  else if(b.dataset.rstat){const f=b.closest("form");f.dataset.statut=b.dataset.rstat;f.querySelectorAll("[data-rstat]").forEach(x=>x.setAttribute("aria-pressed",x===b))}
  else if(b.dataset.pay){budPay(b.dataset.pay)}
  else if(b.dataset.dev){budDev(b.dataset.dev)}
  else if(b.dataset.row){sel.open=sel.open===b.dataset.row?null:b.dataset.row;drawB()}
  else if(b.dataset.edit){budEdit(b.dataset.edit)}
  else if(b.dataset.del){await budDel(b.dataset.del,b)}
  else if(b.id==="bCancel"){budForm()}
  else if(b.dataset.tdel){await todoDel(b.dataset.tdel,b)}
  else if(b.dataset.show){const x=document.getElementById(b.dataset.show),on=x.textContent.startsWith("•");x.textContent=on?x.dataset.sec:"••••••";b.textContent=on?"Cacher":"Afficher"}
  else if(b.id==="lockBtn"){await keyDel();D=null;B=null;ME=null;VY=null;ES={prog:{},resa:{}};tab="now";clearInterval(tick);lock()}});
// --- budget : chiffré pour 2 personnes, stocké dans un dépôt séparé de l'appli ---
const LK="carnet_budget",api=()=>`https://api.github.com/repos/${B.repo}/contents/budget.json`;
let BS={cfg:{maj:0},items:{},todo:{}},sel={dev:"TWD",pay:null,edit:null,open:null},syncing=false;
const money=(n,d)=>new Intl.NumberFormat("fr-FR",{maximumFractionDigits:d==="EUR"?2:0,minimumFractionDigits:d==="EUR"?2:0}).format(n)+(d==="EUR"?" €":" NT$");
function merge(a,b){const out={cfg:(b.cfg?.maj||0)>(a.cfg?.maj||0)?b.cfg:a.cfg,items:{...a.items},todo:{...(a.todo||{})}};
  for(const[k,v]of Object.entries(b.items||{}))if(!out.items[k]||v.maj>out.items[k].maj)out.items[k]=v;
  for(const[k,v]of Object.entries(b.todo||{}))if(!out.todo[k]||v.maj>out.todo[k].maj)out.todo[k]=v;return out}
const pubs=()=>B.membres.map(m=>m.pub);
async function saveLocal(dirty){try{localStorage.setItem(LK,JSON.stringify({env:await sealEnv(BS,pubs()),dirty}))}catch(e){}}
async function loadLocal(){try{const x=JSON.parse(localStorage.getItem(LK));if(x){const o=await openEnv(x.env,ME);if(o)BS=merge(BS,o);return!!x.dirty}}catch(e){}return false}
const stat=t=>{const e=$("#bSt");if(e)e.textContent=t};
async function ghGet(tok){const h={Accept:"application/vnd.github+json"};if(tok)h.Authorization="Bearer "+tok;
  const r=await fetch(api(),{headers:h,cache:"no-store"});if(r.status===404)return{sha:null,env:null};if(!r.ok)throw r.status;
  const j=await r.json();return{sha:j.sha,env:JSON.parse(atob(j.content.replace(/\s/g,"")))}}
async function ghPut(tok,sha){const body={message:"maj",content:btoa(JSON.stringify(await sealEnv(BS,pubs())))};if(sha)body.sha=sha;
  return fetch(api(),{method:"PUT",headers:{Accept:"application/vnd.github+json",Authorization:"Bearer "+tok},body:JSON.stringify(body)})}
let again=false;
async function sync(forceDirty){if(window.__DEMO)return;if(syncing){again=true;return}syncing=true;let dirty=forceDirty||await loadLocal();
  try{for(let n=0;n<4;n++){const g=await ghGet(BS.cfg.token);
      if(g.env){const o=await openEnv(g.env,ME);if(o){dirty=dirty||JSON.stringify(merge(o,BS))!==JSON.stringify(o);BS=merge(BS,o)}}
      if(!g.env&&BS.cfg.token)dirty=true;
      if(!dirty){await saveLocal(false);stat("À jour.");break}
      if(!BS.cfg.token){await saveLocal(true);stat("En attente de l'accès GitHub.");break}
      const p=await ghPut(BS.cfg.token,g.sha);
      if(p.ok){dirty=false;await saveLocal(false);stat("Partagé avec l'autre téléphone.");break}
      if(p.status===409||p.status===422){continue}
      if(p.status===401||p.status===403||p.status===404){await saveLocal(true);stat("L'accès GitHub est refusé ou expiré. Tes dépenses restent sur ce téléphone.");break}
      throw p.status}
  }catch(e){await saveLocal(dirty);stat(dirty?"Pas de réseau. Dépenses gardées ici, envoi plus tard.":"Pas de réseau. Dernière version enregistrée.")}
  syncing=false;drawB();drawT();if(again){again=false;sync()}}
const short=n=>n.length>7?n.slice(0,3)+".":n;
const RMIN=20,RMAX=60,okRate=t=>t>=RMIN&&t<=RMAX,rate=()=>{const t=+BS.cfg.taux;return okRate(t)?t:+B.taux};
function drawB(){if(!$("#bList"))return;conv();const L=Object.values(BS.items).filter(i=>!i.suppr).sort((a,b)=>b.date.localeCompare(a.date)||b.maj-a.maj),tot=[0,0];L.forEach(i=>tot[i.paye]+=i.eur);
  const[a,b]=tot,T=a+b,M=B.membres,d=Math.abs(a-b)/2,hi=a>b?0:1;
  $("#bTok").innerHTML=(!BS.cfg.token&&!window.__DEMO)?`<form id="bTF" class="card" autocomplete="off"><h2 class="sec" style="margin:0">Relier les 2 téléphones</h2><p class="small">À faire une seule fois. Colle l'accès GitHub créé pour le budget.</p><input class="fi" id="bTI" type="password" autocomplete="off" autocapitalize="off" spellcheck="false" aria-label="Accès GitHub"><button class="btn">Relier</button></form>`:"";
  const tf=$("#bTF");if(tf)tf.onsubmit=async e=>{e.preventDefault();const v=$("#bTI").value.trim();if(!v)return;BS.cfg={...BS.cfg,token:v,maj:Date.now()};await sync(true);if(/refusé/.test($("#bSt").textContent)){BS.cfg={...BS.cfg,token:null,maj:Date.now()};drawB();stat("Cet accès ne fonctionne pas. Vérifie-le et recommence.")}};
  $("#bList").innerHTML=L.length?`<section class="card" id="bRec" aria-label="Récap"><h2 class="sec" style="margin:0">Récap</h2><div class="thd"><span>Quoi</span><span>Euros</span><span>Payé par</span></div>
  ${L.map(i=>`<div class="ln"><button type="button" class="trow" data-row="${esc(i.id)}" aria-expanded="${sel.open===i.id}"><span class="q"><b class="lib">${esc(i.lib)}</b><small>${fmt(new Date(i.date+"T12:00:00Z"),"UTC",{day:"numeric",month:"short"})}${i.dev==="TWD"?" · "+money(i.mont,"TWD"):""}</small></span><b class="num">${money(i.eur,"EUR")}</b><span class="tag p${i.paye}">${esc(short(M[i.paye].nom))}</span></button>${sel.open===i.id?`<div class="row"><button class="sm" data-edit="${esc(i.id)}">Modifier</button><button class="sm" data-del="${esc(i.id)}">Supprimer</button></div>`:""}</div>`).join("")}
  </section><section class="tk" id="bTk" aria-label="Total du voyage"><h2>TOTAL DU VOYAGE</h2>${M.map((m,i)=>`<div class="dl"><span>Payé par ${esc(m.nom)}</span><b>${money(tot[i],"EUR")}</b></div>`).join("")}<div class="dl"><span>Part de chacun</span><b>${money(T/2,"EUR")}</b></div><div class="hr"></div><div class="dl big"><span>Total</span><b>${money(T,"EUR")}</b></div><div class="owe">${d<.005?"Vous êtes à égalité":`${esc(M[1-hi].nom)} doit ${money(d,"EUR")} à ${esc(M[hi].nom)}`}</div></section>`:`<div class="empty">Aucune dépense pour l'instant.</div>`}
let convFrom="twd";
const pnum=v=>parseFloat(String(v).replace(/\s/g,"").replace(",","."));
const fnum=(n,d)=>new Intl.NumberFormat("fr-FR",{maximumFractionDigits:d,useGrouping:false}).format(n);
function conv(from){const i=$("#bC"),e=$("#bCe");if(!i)return;if(from)convFrom=from;const t=rate();
  if(convFrom==="twd"){const n=pnum(i.value);e.value=n>=0?fnum(n/t,2):""}else{const n=pnum(e.value);i.value=n>=0?fnum(n*t,0):""}
  $("#bCt").textContent=`1 € = ${String(t).replace(".",",")} NT$`}
function budPay(i){sel.pay=+i;document.querySelectorAll("[data-pay]").forEach(x=>x.setAttribute("aria-pressed",x.dataset.pay===String(i)))}
function budDev(d){sel.dev=d;document.querySelectorAll("[data-dev]").forEach(x=>x.setAttribute("aria-pressed",x.dataset.dev===d))}
function budForm(){sel.edit=null;$("#bF").reset();$("#bD").value=key(nowD(),Intl.DateTimeFormat().resolvedOptions().timeZone);$("#bT").textContent="Ajouter une dépense";$("#bS").textContent="Ajouter";$("#bCancel").hidden=true;$("#bE").hidden=true;budDev(sel.dev);sel.pay=null;document.querySelectorAll("[data-pay]").forEach(x=>x.setAttribute("aria-pressed","false"))}
function budEdit(id){const i=BS.items[id];if(!i)return;sel.edit=id;$("#bL").value=i.lib;$("#bM").value=i.mont;$("#bD").value=i.date;budDev(i.dev);budPay(i.paye);$("#bT").textContent="Modifier la dépense";$("#bS").textContent="Enregistrer";$("#bCancel").hidden=false;$("#bF").scrollIntoView({block:"center"})}
async function budDel(id,btn){if(btn.dataset.sure!=="1"){btn.dataset.sure="1";btn.textContent="Confirmer";return}BS.items[id]={...BS.items[id],suppr:true,maj:Date.now()};await saveLocal(true);drawB();sync(true)}
async function budOpen(){budForm();$("#bC").oninput=()=>conv("twd");$("#bCe").oninput=()=>conv("eur");$("#bRo").onclick=()=>{const f=$("#bRf");f.hidden=!f.hidden;if(!f.hidden){$("#bR").value=String(rate()).replace(".",",");$("#bRe").hidden=true;$("#bR").focus()}};
  $("#bRf").onsubmit=async e=>{e.preventDefault();const n=pnum($("#bR").value),x=$("#bRe");if(!okRate(n)){x.hidden=false;x.textContent=`Ce taux semble faux. Écris un nombre entre ${RMIN} et ${RMAX}, par exemple 36,1.`;return}BS.cfg={...BS.cfg,taux:n,maj:Date.now()};$("#bRf").hidden=true;conv();await saveLocal(true);sync(true)};
  $("#bF").onsubmit=async e=>{e.preventDefault();const E=$("#bE"),n=parseFloat($("#bM").value.replace(/\s/g,"").replace(",","."));
    if(!(n>0)){E.hidden=false;E.textContent="Écris un montant, par exemple 350.";return}if(sel.pay===null){E.hidden=false;E.textContent="Choisis qui a payé.";return}
    const old=sel.edit&&BS.items[sel.edit],taux=old&&old.dev===sel.dev&&sel.dev==="TWD"&&okRate(+old.taux)?old.taux:rate(),id=sel.edit||Date.now().toString(36)+u8(crypto.getRandomValues(new Uint8Array(4))).replace(/\W/g,"");
    BS.items[id]={id,lib:$("#bL").value.trim().slice(0,80),mont:n,dev:sel.dev,taux,eur:sel.dev==="EUR"?n:Math.round(n/taux*100)/100,date:$("#bD").value,paye:sel.pay,maj:Date.now()};
    sel.open=null;await saveLocal(true);budForm();drawB();sync(true)};
  await loadLocal();drawB();sync()}
addEventListener("online",()=>{if(B&&(tab==="bud"||tab==="todo"))sync()});
// --- To Do : même coffre chiffré que le budget, partagé entre les 2 téléphones ---
const TODO0=[]; // aucune tâche écrite en clair : tout se saisit dans l'appli, chiffré
const todos=()=>{const A={};TODO0.forEach(t=>A[t.id]=t);Object.entries(BS.todo||{}).forEach(([k,v])=>{if(!A[k]||v.maj>=A[k].maj)A[k]=v});return Object.values(A).filter(t=>!t.suppr).sort((a,b)=>a.ordre-b.ordre)};
let dragT=null,drawLater=false;
function drawT(){const box=$("#tList");if(!box)return;if(dragT){drawLater=true;return}const L=todos(),n=L.filter(t=>t.fait).length;
  $("#tCount").textContent=!L.length?"":n===L.length?"Tout est fait. Bravo !":`${n} sur ${L.length} fait${n>1?"s":""}.`;
  box.innerHTML=L.length?L.map(t=>`<div class="ti${t.fait?" done":""}" data-tid="${esc(t.id)}"><button type="button" class="grip" data-grip="${esc(t.id)}" aria-label="Déplacer : ${esc(t.lib)}. Flèches haut et bas."><svg viewBox="0 0 24 24" aria-hidden="true"><path d="M9 6h.01M15 6h.01M9 12h.01M15 12h.01M9 18h.01M15 18h.01"/></svg></button><label class="check"><input type="checkbox" data-todo="${esc(t.id)}" ${t.fait?"checked":""}><span>${esc(t.lib)}</span></label><button type="button" class="tx" data-tdel="${esc(t.id)}" aria-label="Supprimer : ${esc(t.lib)}">×</button></div>`).join(""):`<p class="small">Rien à faire pour l'instant.</p>`}
const todoSet=async(id,ch)=>{const t=todos().find(x=>x.id===id);if(!t)return;BS.todo={...BS.todo,[id]:{...t,...ch,maj:Date.now()}};await saveLocal(true);drawT();sync(true)};
async function todoDel(id,btn){if(btn.dataset.sure!=="1"){btn.dataset.sure="1";btn.textContent="Supprimer ?";btn.classList.add("sure");return}await todoSet(id,{suppr:true})}
// nouvel ordre : on renumérote, seules les tâches qui ont bougé sont envoyées
async function todoOrder(ids){const L=todos(),A={};L.forEach(t=>A[t.id]=t);const now=Date.now();let ch=false;
  ids.forEach((id,i)=>{const t=A[id];if(t&&t.ordre!==i+1){BS.todo={...BS.todo,[id]:{...t,ordre:i+1,maj:now}};ch=true}});
  if(ch){await saveLocal(true);drawT();sync(true)}}
// glisser avec le doigt (ou la souris), par la poignée à gauche
root.addEventListener("pointerdown",e=>{const g=e.target.closest("[data-grip]");if(!g||dragT)return;e.preventDefault();
  const row=g.closest(".ti"),rows=[...document.querySelectorAll("#tList .ti")],h=row.getBoundingClientRect().height;
  dragT={row,rows,from:rows.indexOf(row),to:rows.indexOf(row),y0:e.clientY,mid:rows.map(r=>{const b=r.getBoundingClientRect();return b.top+b.height/2}),h};
  g.setPointerCapture(e.pointerId);row.classList.add("drag");
  const move=ev=>{const d=dragT,dy=ev.clientY-d.y0,c=d.mid[d.from]+dy;let to=d.from;
      d.mid.forEach((m,i)=>{if(i<d.from&&c<m)to=Math.min(to,i);if(i>d.from&&c>m)to=Math.max(to,i)});d.to=to;
      d.rows.forEach((r,i)=>{if(r===d.row)return;r.style.transform=(i>d.from&&i<=to)?`translateY(${-d.h}px)`:(i<d.from&&i>=to)?`translateY(${d.h}px)`:""});
      d.row.style.transform=`translateY(${dy}px)`},
    end=async()=>{g.removeEventListener("pointermove",move);g.removeEventListener("pointerup",end);g.removeEventListener("pointercancel",end);
      const d=dragT,ids=d.rows.map(r=>r.dataset.tid),[m]=ids.splice(d.from,1);ids.splice(d.to,0,m);
      d.rows.forEach(r=>{r.style.transform="";r.classList.remove("drag")});dragT=null;
      if(d.to!==d.from)await todoOrder(ids);else if(drawLater)drawT();drawLater=false;
      const ng=document.querySelector(`[data-grip="${CSS.escape(m)}"]`);if(ng&&d.kb)ng.focus()};
  g.addEventListener("pointermove",move);g.addEventListener("pointerup",end);g.addEventListener("pointercancel",end)});
// clavier : flèches haut / bas sur la poignée
root.addEventListener("keydown",async e=>{const g=e.target.closest("[data-grip]");if(!g||!/^Arrow(Up|Down)$/.test(e.key))return;e.preventDefault();
  const ids=todos().map(t=>t.id),i=ids.indexOf(g.dataset.grip),j=i+(e.key==="ArrowUp"?-1:1);if(j<0||j>=ids.length)return;
  [ids[i],ids[j]]=[ids[j],ids[i]];await todoOrder(ids);const ng=document.querySelector(`[data-grip="${CSS.escape(ids[j])}"]`);if(ng)ng.focus()});
root.addEventListener("change",e=>{const c=e.target.closest("[data-todo]");if(c)todoSet(c.dataset.todo,{fait:c.checked})});
async function todoOpen(){$("#tF").onsubmit=async e=>{e.preventDefault();const v=$("#tI").value.trim().slice(0,80);if(!v)return;
    const id="t"+Date.now().toString(36)+u8(crypto.getRandomValues(new Uint8Array(3))).replace(/\W/g,"");$("#tI").value="";
    BS.todo={...BS.todo,[id]:{id,lib:v,fait:false,ordre:Math.max(0,...todos().map(t=>t.ordre))+1,maj:Date.now()}};await saveLocal(true);drawT();sync(true)};
  drawT();await loadLocal();drawT();sync()}
async function initB(priv){ME=priv;B=null;if(window.__DEMO_B){B=window.__DEMO_B.acces;BS=window.__DEMO_B.etat;return}
  if(F&&F.prive){try{const o=await openEnv(F.prive,priv);if(o&&o.budget)B=o.budget}catch(e){}}}
function start(data,when){D=data;up=when;if(VY&&tab==="now")tab="voy";render();clearInterval(tick);tick=setInterval(()=>{const a=$("#cT"),f=$("#cF"),n=nowD();if(a){a.textContent=hm(n,TZ.TPE);f.textContent=hm(n,TZ.MRS);$("#dT").textContent=day(n,TZ.TPE);$("#dF").textContent=day(n,TZ.MRS)}},2e4)}
async function loadFile(){const r=await fetch("carnet.json");if(!r.ok)throw 0;return r.json()}
const stamp=f=>new Date(f.updated).toLocaleDateString("fr-FR",{day:"numeric",month:"long",hour:"2-digit",minute:"2-digit"});
let F;
function lock(msg){root.innerHTML=`<main class="page lock"><h1>Carnet</h1><p>Écris ta phrase secrète pour ouvrir.</p>
  <form id="f" class="card" autocomplete="off"><label for="ph" class="small muted">Phrase secrète (5 mots)</label>
  <input id="ph" type="password" autocapitalize="off" autocorrect="off" spellcheck="false" autocomplete="off">
  <label class="check"><input id="sh" type="checkbox"><span>Montrer la phrase</span></label>
  <label class="check"><input id="keep" type="checkbox" checked><span>Rester ouvert sur ce téléphone. À décocher sur un appareil partagé.</span></label>
  ${msg?`<p class="err" role="alert">${esc(msg)}</p>`:""}<button class="btn" id="go">Ouvrir</button></form></main>`;
  $("#sh").onchange=e=>{$("#ph").type=e.target.checked?"text":"password"};
  $("#f").onsubmit=async e=>{e.preventDefault();const g=$("#go"),p=$("#ph").value,k=$("#keep").checked;g.disabled=true;g.textContent="Ouverture…";await new Promise(r=>setTimeout(r,30));
    try{const priv=await privFromPhrase(F,p);if(!priv)return lock("Phrase incorrecte. Vérifie les 5 mots.");
      const d=await openData(F,priv);if(!d)return lock("Cette phrase n'ouvre plus le carnet. Demande une nouvelle phrase.");
      if(k)await keyPut(priv);await initB(priv);await initV(priv);start(d,stamp(F))}catch(x){lock("Ouverture impossible sur ce navigateur. Essaie Safari ou Chrome à jour.")}}}
(async()=>{if("serviceWorker"in navigator)navigator.serviceWorker.register("sw.js").catch(()=>{});
  if(window.__DEMO){await initB(null);VY=window.__DEMO_V||null;if(window.__DEMO_E)ES=window.__DEMO_E;start(window.__DEMO,"(aperçu)");return}
  try{F=await loadFile();VF=await fetch("voyage.json").then(r=>r.ok?r.json():null).catch(()=>null)}catch(e){root.innerHTML=`<main class="page lock"><h1>Carnet</h1><p class="err">Pas de connexion, et le carnet n'est pas encore enregistré sur ce téléphone. Ouvre-le une fois avec Internet.</p></main>`;return}
  const k=await keyGet();if(k){const d=await openData(F,k).catch(()=>null);if(d){await initB(k);await initV(k);return start(d,stamp(F))}await keyDel();return lock("Le carnet a changé de clés. Écris ta nouvelle phrase.")}
  lock()})();
