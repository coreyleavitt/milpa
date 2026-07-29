import base64, hashlib, json
b = json.load(open("conformance/spec-v1/_oracle/attestation/index.kdl.bundle"))
# locate the tlog entry + recorded envelopeHash + logIndex
tlog = b["verificationMaterial"]["tlogEntries"][0]
body = json.loads(base64.b64decode(tlog["canonicalizedBody"]))
rec = body["spec"]["envelopeHash"]["value"]
print("logIndex:", tlog.get("logIndex"))
print("recorded envelopeHash (Rekor):", rec)
# DSSE envelope from the bundle
env = b["dsseEnvelope"]
pt = env["payloadType"]; payload_b64 = env["payload"]
sig = env["signatures"][0].get("sig",""); keyid = env["signatures"][0].get("keyid","")
payload_raw = base64.b64decode(payload_b64)
# Form A: cosign Go json.Marshal form (secure-systems-lab dsse): payloadType-first, keyid present (no omitempty), std base64
goform = ('{"payloadType":"%s","payload":"%s","signatures":[{"keyid":"%s","sig":"%s"}]}'
          % (pt, payload_b64, keyid, sig)).encode()
print("sha256(cosign Go form)   :", hashlib.sha256(goform).hexdigest())
# Form B: protobuf-JSON (prost) form: payload-first tag order, keyid omitted when empty
pbform = json.dumps({"payload": payload_b64, "payloadType": pt,
                     "signatures":[{"sig": sig}]}, separators=(",",":")).encode()
print("sha256(protobuf-JSON)    :", hashlib.sha256(pbform).hexdigest())
print("match Rekor==Go  :", hashlib.sha256(goform).hexdigest()==rec)
print("match Rekor==pbjson:", hashlib.sha256(pbform).hexdigest()==rec)
