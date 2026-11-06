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
async function openData(file,priv){
  const eph=await S.importKey("raw",b64(file.data.eph),{name:"ECDH",namedCurve:"P-256"},false,[]);
  const bits=await S.deriveBits({name:"ECDH",public:eph},priv,256);
  const hk=await S.importKey("raw",bits,"HKDF",false,["deriveKey"]);
  const wk=await S.deriveKey({name:"HKDF",hash:"SHA-256",salt:new Uint8Array(0),info:te.encode("carnet-v1")},hk,{name:"AES-GCM",length:256},false,["decrypt"]);
  for(const w of file.data.wraps){try{const dek=await S.decrypt({name:"AES-GCM",iv:b64(w.iv)},wk,b64(w.ct));
    const dk=await S.importKey("raw",dek,"AES-GCM",false,["decrypt"]);
    return JSON.parse(td.decode(await S.decrypt({name:"AES-GCM",iv:b64(file.data.iv)},dk,b64(file.data.ct))))}catch(e){}}
  return null}
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
const I={now:'<circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/>',vol:'<path d="M21 3 3 10l7 3 3 7z"/><path d="m10 13 5-5"/>',sej:'<path d="M3 11 12 4l9 7"/><path d="M5 10v10h14V10"/><path d="M10 20v-6h4v6"/>',urg:'<path d="M5 4h4l2 5-3 2a12 12 0 0 0 5 5l2-3 5 2v4a2 2 0 0 1-2 2A16 16 0 0 1 3 6a2 2 0 0 1 2-2z"/>'};
const TABS=[["now","Maintenant"],["vol","Vols"],["sej","Planning"],["urg","Urgences"]];
let D,tab="now",up="",tick;
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
const V={
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
 urg(){return `<h1 class="h">Urgences</h1>
  <h2 class="sec" style="margin-top:0">Sur place, à Taïwan</h2>
  ${D.urgences.map(u=>`<div class="card"><b>${esc(u.nom)}</b>${u.note?`<span class="small muted">${esc(u.note)}</span>`:""}<div class="call"><b>${esc(u.tel)}</b><a href="tel:${esc(u.tel.replace(/[^+\d]/g,""))}">Appeler</a></div></div>`).join("")}
  <h2 class="sec">Avant de partir</h2>${D.avant.map(t=>`<div class="card"><b>${esc(t.titre)}</b><span class="small">${esc(t.texte)}</span></div>`).join("")}
  <div class="foot"><span>Mis à jour le ${esc(up)}</span><button class="btn alt" id="lockBtn">Verrouiller sur cet appareil</button></div>`}};
function render(){root.innerHTML=`<main class="page">${V[tab]()}</main><nav class="nav" aria-label="Rubriques">${TABS.map(([k,l])=>`<button data-tab="${k}" ${k===tab?'aria-current="page"':""}><svg viewBox="0 0 24 24" aria-hidden="true">${I[k]}</svg>${l}</button>`).join("")}</nav>`;scrollTo(0,0)}
root.addEventListener("click",async e=>{const b=e.target.closest("button");if(!b)return;
  if(b.dataset.tab){tab=b.dataset.tab;render()}
  else if(b.dataset.show){const x=document.getElementById(b.dataset.show),on=x.textContent.startsWith("•");x.textContent=on?x.dataset.sec:"••••••";b.textContent=on?"Cacher":"Afficher"}
  else if(b.id==="lockBtn"){await keyDel();D=null;clearInterval(tick);lock()}});
function start(data,when){D=data;up=when;render();clearInterval(tick);tick=setInterval(()=>{const a=$("#cT"),f=$("#cF"),n=nowD();if(a){a.textContent=hm(n,TZ.TPE);f.textContent=hm(n,TZ.MRS);$("#dT").textContent=day(n,TZ.TPE);$("#dF").textContent=day(n,TZ.MRS)}},2e4)}
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
      if(k)await keyPut(priv);start(d,stamp(F))}catch(x){lock("Ouverture impossible sur ce navigateur. Essaie Safari ou Chrome à jour.")}}}
(async()=>{if("serviceWorker"in navigator)navigator.serviceWorker.register("sw.js").catch(()=>{});
  if(window.__DEMO){start(window.__DEMO,"(aperçu)");return}
  try{F=await loadFile()}catch(e){root.innerHTML=`<main class="page lock"><h1>Carnet</h1><p class="err">Pas de connexion, et le carnet n'est pas encore enregistré sur ce téléphone. Ouvre-le une fois avec Internet.</p></main>`;return}
  const k=await keyGet();if(k){const d=await openData(F,k).catch(()=>null);if(d)return start(d,stamp(F));await keyDel();return lock("Le carnet a changé de clés. Écris ta nouvelle phrase.")}
  lock()})();
