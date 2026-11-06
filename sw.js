const C="carnet-v6",APP=["./","index.html","app.js","style.css","manifest.json","icon-192.png","icon-512.png","icon-maskable-512.png","fonts/fredoka-latin-600-normal.woff2","fonts/atkinson-hyperlegible-latin-400-normal.woff2","fonts/atkinson-hyperlegible-latin-700-normal.woff2"];
self.addEventListener("install",e=>e.waitUntil(caches.open(C).then(c=>c.addAll(APP.concat("carnet.json"))).then(()=>self.skipWaiting())));
self.addEventListener("activate",e=>e.waitUntil(caches.keys().then(k=>Promise.all(k.filter(x=>x!==C).map(x=>caches.delete(x)))).then(()=>self.clients.claim())));
// Réseau d'abord (données fraîches), sinon copie enregistrée (hors connexion). Seule la version chiffrée est gardée.
self.addEventListener("fetch",e=>{const r=e.request;if(r.method!=="GET"||new URL(r.url).origin!==location.origin)return;
e.respondWith(fetch(r,{cache:"no-cache"}).then(x=>{if(x.ok){const c=x.clone();caches.open(C).then(k=>k.put(r,c))}return x}).catch(()=>caches.match(r,{ignoreSearch:true})))});
