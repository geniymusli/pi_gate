import json, subprocess, secrets, shutil, time
P = "/etc/gate/chain.json"
shutil.copy(P, "/tmp/chain.json.bak-%d" % int(time.time()))
c = json.load(open(P))
c["sni"] = "ya.ru"
c["target"] = "ya.ru:443"

def x25519():
    out = subprocess.check_output(["xray", "x25519"]).decode()
    priv = pub = None
    for line in out.splitlines():
        low = line.lower()
        if "private" in low:
            priv = line.split(":")[-1].strip()
        elif "public" in low:
            pub = line.split(":")[-1].strip()
    if not priv or not pub:
        raise SystemExit("x25519 parse failed: %r" % out)
    return priv, pub

for h in c["hops"]:
    h["uuid"] = subprocess.check_output(["xray", "uuid"]).decode().strip()
    h["privkey"], h["pubkey"] = x25519()
    h["shortid"] = secrets.token_hex(4)

json.dump(c, open(P, "w"), indent=2)
print("OK sni=%s target=%s" % (c["sni"], c["target"]))
for h in c["hops"]:
    print("  %-4s uuid=%s.. pub=%s.. sid=%s" % (h["name"], h["uuid"][:8], h["pubkey"][:10], h["shortid"]))
