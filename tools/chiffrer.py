#!/usr/bin/env python3
"""Chiffre le contenu pour les membres. Usage : chiffrer.py source.json membres.json carnet.json
membres.json ne contient que des clés publiques et des clés privées chiffrées : aucun secret n'est nécessaire ici."""
import json,os,sys,base64,datetime as dt
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes,serialization as ser
e=lambda b:base64.b64encode(b).decode();d=base64.b64decode
src,mem,out=sys.argv[1:4];m=json.load(open(mem))
assert m["kdf"]["iter"]>=600000 and len(m["slots"])>=1
for s in m["slots"]: assert set(s)=={"pub","iv","priv"}
SRC=json.load(open(src));PRIV=SRC.pop("prive",None)
pt=json.dumps(SRC,ensure_ascii=False,separators=(",",":")).encode()
pt+=b" "*(4096-len(pt)%4096)  # masque la taille exacte du contenu
def seal(pt,slots):
  dek=AESGCM.generate_key(256);iv=os.urandom(12);eph=ec.generate_private_key(ec.SECP256R1());wraps=[]
  for s in slots:
    pub=ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(),d(s["pub"]))
    k=HKDF(hashes.SHA256(),32,salt=b"",info=b"carnet-v1").derive(eph.exchange(ec.ECDH(),pub))
    i=os.urandom(12);wraps.append({"iv":e(i),"ct":e(AESGCM(k).encrypt(i,dek,None))})
  pubb=eph.public_key().public_bytes(ser.Encoding.X962,ser.PublicFormat.UncompressedPoint)
  return {"eph":e(pubb),"wraps":wraps,"iv":e(iv),"ct":e(AESGCM(dek).encrypt(iv,pt,None))}
out_d={"v":1,"updated":dt.datetime.now(dt.timezone.utc).isoformat(),"kdf":m["kdf"],"slots":m["slots"],"data":seal(pt,m["slots"])}
if PRIV:  # visible seulement par les membres listés (Budget)
  idx=PRIV["membres"];b=PRIV["budget"]
  b["membres"]=[{"nom":n,"pub":m["slots"][i]["pub"]} for n,i in zip(b["noms"],idx)];del b["noms"]
  q=json.dumps({"budget":b},ensure_ascii=False).encode();q+=b" "*(4096-len(q)%4096)
  out_d["prive"]=seal(q,[m["slots"][i] for i in idx])
json.dump(out_d,open(out,"w"))
print("ok",out,"membres:",len(m["slots"]),"prive:",bool(PRIV))
