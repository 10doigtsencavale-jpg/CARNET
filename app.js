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
const I={now:'<circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/>',vol:'<path d="M21 3 3 10l7 3 3 7z"/><path d="m10 13 5-5"/>',sej:'<path d="M3 11 12 4l9 7"/><path d="M5 10v10h14V10"/><path d="M10 20v-6h4v6"/>',bud:'<rect x="3" y="6" width="18" height="13" rx="2"/><path d="M3 10h18"/><path d="M16 15h2"/>',urg:'<path d="M5 4h4l2 5-3 2a12 12 0 0 0 5 5l2-3 5 2v4a2 2 0 0 1-2 2A16 16 0 0 1 3 6a2 2 0 0 1 2-2z"/>'};
const TABS=[["now","Maintenant"],["vol","Vols"],["sej","Planning"],["urg","Urgences"]];
let D,tab="now",up="",tick,B=null,ME=null;
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
 bud(){return `<h1 class="h">Budget</h1><div id="bSum"></div><div id="bTok"></div>
  <form id="bF" class="card" autocomplete="off"><h2 id="bT" class="sec" style="margin:0">Ajouter une dépense</h2>
  <label class="small muted" for="bL">Quoi</label><input class="fi" id="bL" required maxlength="80" autocomplete="off">
  <div class="two"><div><label class="small muted" for="bM">Montant</label><input class="fi" id="bM" required inputmode="decimal" autocomplete="off"></div>
  <div><label class="small muted" for="bD">Date</label><input class="fi" id="bD" type="date" required></div></div>
  <div class="seg" role="group" aria-label="Monnaie">${["TWD","EUR"].map(d=>`<button type="button" data-dev="${d}">${d==="TWD"?"Dollars taïwanais":"Euros"}</button>`).join("")}</div>
  <span class="small muted">Qui a payé ?</span><div class="seg pay" role="group" aria-label="Qui a payé">${B.membres.map((m,i)=>`<button type="button" data-pay="${i}" class="p${i}">${esc(m.nom)}</button>`).join("")}</div>
  <p class="err" id="bE" role="alert" hidden></p><button class="btn" id="bS">Enregistrer</button><button type="button" class="btn alt" id="bCancel" hidden>Annuler</button></form>
  <div id="bList" style="display:contents"></div><p class="small muted" id="bSt" style="text-align:center"></p>`},
 urg(){return `<h1 class="h">Urgences</h1>
  <h2 class="sec" style="margin-top:0">Sur place, à Taïwan</h2>
  ${D.urgences.map(u=>`<div class="card"><b>${esc(u.nom)}</b>${u.note?`<span class="small muted">${esc(u.note)}</span>`:""}<div class="call"><b>${esc(u.tel)}</b><a href="tel:${esc(u.tel.replace(/[^+\d]/g,""))}">Appeler</a></div></div>`).join("")}
  <h2 class="sec">Avant de partir</h2>${D.avant.map(t=>`<div class="card"><b>${esc(t.titre)}</b><span class="small">${esc(t.texte)}</span></div>`).join("")}
  <div class="foot"><span>Mis à jour le ${esc(up)}</span><button class="btn alt" id="lockBtn">Verrouiller sur cet appareil</button></div>`}};
function render(){const T=B?TABS.slice(0,3).concat([["bud","Budget"]],TABS.slice(3)):TABS;root.innerHTML=`<main class="page">${V[tab]()}</main><nav class="nav" style="grid-template-columns:repeat(${T.length},minmax(0,1fr))" aria-label="Rubriques">${T.map(([k,l])=>`<button data-tab="${k}" ${k===tab?'aria-current="page"':""}><svg viewBox="0 0 24 24" aria-hidden="true">${I[k]}</svg>${l}</button>`).join("")}</nav>`;scrollTo(0,0);if(tab==="bud")budOpen()}
root.addEventListener("click",async e=>{const b=e.target.closest("button");if(!b)return;
  if(b.dataset.tab){tab=b.dataset.tab;render()}
  else if(b.dataset.pay){budPay(b.dataset.pay)}
  else if(b.dataset.dev){budDev(b.dataset.dev)}
  else if(b.dataset.edit){budEdit(b.dataset.edit)}
  else if(b.dataset.del){await budDel(b.dataset.del,b)}
  else if(b.id==="bCancel"){budForm()}
  else if(b.dataset.show){const x=document.getElementById(b.dataset.show),on=x.textContent.startsWith("•");x.textContent=on?x.dataset.sec:"••••••";b.textContent=on?"Cacher":"Afficher"}
  else if(b.id==="lockBtn"){await keyDel();D=null;B=null;ME=null;tab="now";clearInterval(tick);lock()}});
// --- budget : chiffré pour 2 personnes, stocké dans un dépôt séparé de l'appli ---
const LK="carnet_budget",api=()=>`https://api.github.com/repos/${B.repo}/contents/budget.json`;
let BS={cfg:{maj:0},items:{}},sel={dev:"TWD",pay:null,edit:null},syncing=false;
const money=(n,d)=>new Intl.NumberFormat("fr-FR",{maximumFractionDigits:d==="EUR"?2:0,minimumFractionDigits:d==="EUR"?2:0}).format(n)+(d==="EUR"?" €":" NT$");
function merge(a,b){const out={cfg:(b.cfg?.maj||0)>(a.cfg?.maj||0)?b.cfg:a.cfg,items:{...a.items}};
  for(const[k,v]of Object.entries(b.items||{}))if(!out.items[k]||v.maj>out.items[k].maj)out.items[k]=v;return out}
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
  syncing=false;drawB();if(again){again=false;sync()}}
function drawB(){if(!$("#bSum"))return;const L=Object.values(BS.items).filter(i=>!i.suppr).sort((a,b)=>b.date.localeCompare(a.date)||b.maj-a.maj),tot=[0,0];L.forEach(i=>tot[i.paye]+=i.eur);
  const[a,b]=tot,T=a+b,M=B.membres,d=Math.abs(a-b)/2,hi=a>b?0:1;
  $("#bSum").innerHTML=`<section class="now"><span class="eb">Total, en euros</span><span class="t">${money(T,"EUR")}</span></section>
  <div class="clocks">${M.map((m,i)=>`<div class="clock"><b style="font-size:24px">${money(tot[i],"EUR")}</b><span>payé par ${esc(m.nom)}</span></div>`).join("")}</div>
  <p class="small muted">${d<.005?"Vous êtes à égalité.":`Pour partager à parts égales : ${esc(M[1-hi].nom)} doit ${money(d,"EUR")} à ${esc(M[hi].nom)}.`}</p>
  <div class="card"><label class="small muted" for="bR">Taux utilisé : 1 € = combien de NT$ ?</label><input class="fi" id="bR" inputmode="decimal" value="${esc(BS.cfg.taux||B.taux)}"><span class="small muted">Change les prochaines dépenses, pas les anciennes.</span></div>`;
  $("#bR").onchange=async e=>{const n=parseFloat(e.target.value.replace(",","."));if(n>0){BS.cfg={...BS.cfg,taux:n,maj:Date.now()};await saveLocal(true);sync(true)}};
  $("#bTok").innerHTML=(!BS.cfg.token&&!window.__DEMO)?`<form id="bTF" class="card" autocomplete="off"><h2 class="sec" style="margin:0">Relier les 2 téléphones</h2><p class="small">À faire une seule fois. Colle l'accès GitHub créé pour le budget.</p><input class="fi" id="bTI" type="password" autocomplete="off" autocapitalize="off" spellcheck="false" aria-label="Accès GitHub"><button class="btn">Relier</button></form>`:"";
  const tf=$("#bTF");if(tf)tf.onsubmit=async e=>{e.preventDefault();const v=$("#bTI").value.trim();if(!v)return;BS.cfg={...BS.cfg,token:v,maj:Date.now()};await sync(true);if(/refusé/.test($("#bSt").textContent)){BS.cfg={...BS.cfg,token:null,maj:Date.now()};drawB();stat("Cet accès ne fonctionne pas. Vérifie-le et recommence.")}};
  $("#bList").innerHTML=L.length?`<h2 class="sec">Dépenses</h2>`+L.map(i=>`<article class="card exp"><div class="kv"><b class="lib">${esc(i.lib)}</b><b>${money(i.mont,i.dev)}</b></div>
   <div class="kv small"><span class="muted">${fmt(new Date(i.date+"T12:00:00Z"),"UTC",{day:"numeric",month:"long"})}${i.dev==="TWD"?" · "+money(i.eur,"EUR"):""}</span><span class="tag p${i.paye}">${esc(M[i.paye].nom)}</span></div>
   <div class="row"><button class="sm" data-edit="${esc(i.id)}">Modifier</button><button class="sm" data-del="${esc(i.id)}">Supprimer</button></div></article>`).join(""):`<div class="empty">Aucune dépense pour l'instant.</div>`}
function budPay(i){sel.pay=+i;document.querySelectorAll("[data-pay]").forEach(x=>x.setAttribute("aria-pressed",x.dataset.pay===String(i)))}
function budDev(d){sel.dev=d;document.querySelectorAll("[data-dev]").forEach(x=>x.setAttribute("aria-pressed",x.dataset.dev===d))}
function budForm(){sel.edit=null;$("#bF").reset();$("#bD").value=key(nowD(),Intl.DateTimeFormat().resolvedOptions().timeZone);$("#bT").textContent="Ajouter une dépense";$("#bCancel").hidden=true;$("#bE").hidden=true;budDev(sel.dev);sel.pay=null;document.querySelectorAll("[data-pay]").forEach(x=>x.setAttribute("aria-pressed","false"))}
function budEdit(id){const i=BS.items[id];if(!i)return;sel.edit=id;$("#bL").value=i.lib;$("#bM").value=i.mont;$("#bD").value=i.date;budDev(i.dev);budPay(i.paye);$("#bT").textContent="Modifier la dépense";$("#bCancel").hidden=false;$("#bF").scrollIntoView({block:"center"})}
async function budDel(id,btn){if(btn.dataset.sure!=="1"){btn.dataset.sure="1";btn.textContent="Confirmer";return}BS.items[id]={...BS.items[id],suppr:true,maj:Date.now()};await saveLocal(true);drawB();sync(true)}
async function budOpen(){budForm();$("#bF").onsubmit=async e=>{e.preventDefault();const E=$("#bE"),n=parseFloat($("#bM").value.replace(/\s/g,"").replace(",","."));
    if(!(n>0)){E.hidden=false;E.textContent="Écris un montant, par exemple 350.";return}if(sel.pay===null){E.hidden=false;E.textContent="Choisis qui a payé.";return}
    const old=sel.edit&&BS.items[sel.edit],taux=old&&old.dev===sel.dev&&sel.dev==="TWD"?old.taux:+(BS.cfg.taux||B.taux),id=sel.edit||Date.now().toString(36)+u8(crypto.getRandomValues(new Uint8Array(4))).replace(/\W/g,"");
    BS.items[id]={id,lib:$("#bL").value.trim().slice(0,80),mont:n,dev:sel.dev,taux,eur:sel.dev==="EUR"?n:Math.round(n/taux*100)/100,date:$("#bD").value,paye:sel.pay,maj:Date.now()};
    await saveLocal(true);budForm();drawB();sync(true)};
  await loadLocal();drawB();sync()}
addEventListener("online",()=>{if(B&&tab==="bud")sync()});
async function initB(priv){ME=priv;B=null;if(window.__DEMO_B){B=window.__DEMO_B.acces;BS=window.__DEMO_B.etat;return}
  if(F&&F.prive){try{const o=await openEnv(F.prive,priv);if(o&&o.budget)B=o.budget}catch(e){}}}
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
      if(k)await keyPut(priv);await initB(priv);start(d,stamp(F))}catch(x){lock("Ouverture impossible sur ce navigateur. Essaie Safari ou Chrome à jour.")}}}
(async()=>{if("serviceWorker"in navigator)navigator.serviceWorker.register("sw.js").catch(()=>{});
  if(window.__DEMO){await initB(null);start(window.__DEMO,"(aperçu)");return}
  try{F=await loadFile()}catch(e){root.innerHTML=`<main class="page lock"><h1>Carnet</h1><p class="err">Pas de connexion, et le carnet n'est pas encore enregistré sur ce téléphone. Ouvre-le une fois avec Internet.</p></main>`;return}
  const k=await keyGet();if(k){const d=await openData(F,k).catch(()=>null);if(d){await initB(k);return start(d,stamp(F))}await keyDel();return lock("Le carnet a changé de clés. Écris ta nouvelle phrase.")}
  lock()})();
