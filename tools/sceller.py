#!/usr/bin/env python3
"""Chiffre un fichier pour les 4 membres, avec leurs clés publiques prises dans carnet.json.
Usage : sceller.py source.json carnet.json sortie.json
Aucun secret n'est nécessaire : seules les clés publiques servent. Le fichier source
(en clair) reste hors du dépôt public (dossier work/, ignoré par git)."""
import json, os, sys, base64, datetime as dt
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization as ser

e = lambda b: base64.b64encode(b).decode()
d = base64.b64decode


def seal(pt, pubs):
    pt += b" " * (4096 - len(pt) % 4096)  # masque la taille exacte du contenu
    dek = AESGCM.generate_key(256)
    iv = os.urandom(12)
    eph = ec.generate_private_key(ec.SECP256R1())
    wraps = []
    for p in pubs:
        pub = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), d(p))
        k = HKDF(hashes.SHA256(), 32, salt=b"", info=b"carnet-v1").derive(eph.exchange(ec.ECDH(), pub))
        i = os.urandom(12)
        wraps.append({"iv": e(i), "ct": e(AESGCM(k).encrypt(i, dek, None))})
    pubb = eph.public_key().public_bytes(ser.Encoding.X962, ser.PublicFormat.UncompressedPoint)
    return {"eph": e(pubb), "wraps": wraps, "iv": e(iv), "ct": e(AESGCM(dek).encrypt(iv, pt, None))}


if __name__ == "__main__":
    src, carnet, out = sys.argv[1:4]
    pubs = [s["pub"] for s in json.load(open(carnet))["slots"]]
    assert len(pubs) >= 1
    data = json.load(open(src))
    pt = json.dumps(data, ensure_ascii=False, separators=(",", ":")).encode()
    json.dump({"v": 1, "updated": dt.datetime.now(dt.timezone.utc).isoformat(), "data": seal(pt, pubs)}, open(out, "w"))
    print("ok", out, "membres:", len(pubs))
