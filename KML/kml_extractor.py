python3 - <<'PY'
from pathlib import Path
from urllib.parse import unquote
import json
import re

txt = Path("stream_round4.txt").read_text(errors="ignore")

m = re.search(
    r'a=SendMessage.*?\r?\n\r?\nrequests=(.*?)&automatic=false',
    txt,
    re.S
)

if not m:
    raise SystemExit("No se encontró el bloque SendMessage")

decoded = unquote(m.group(1))
data = json.loads(decoded)

plain = data[0]["PlainBody"]

start = plain.find("<?xml")
end = plain.rfind("</kml>") + len("</kml>")

kml = plain[start:end]
kml = kml.replace('\\"', '"').replace("\\n", "\n")

Path("S3cr3t.kml").write_text(kml, encoding="utf-8")

print("[+] KML extraído como S3cr3t.kml")
print("[+] Primeras líneas:")
print(kml[:300])
PY
