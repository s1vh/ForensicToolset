from pathlib import Path
import csv
import re
from ipaddress import ip_address

BASE = Path.home() / "forense_challenge02"
TSV = BASE / "parsed_evtx" / "tsv" / "events_window_2015-12-12_0300-0330Z.tsv"
OUT = BASE / "logs" / "74_incident_core_timeline.txt"

KEY_EVENT_IDS = {
    "4624", "4625", "4634", "4647", "4648", "4672",
    "4720", "4722", "4724", "4725", "4728", "4732", "4733", "4738",
    "7040", "7045", "1074", "6005", "6006",
    "21", "22", "23", "24", "39", "40", "41", "42", "54",
    "1010", "1012", "1027"
}

KEYWORDS = re.compile(
    r"(master|administrator|builtin\\administrators|builtin\\users|anonymous|"
    r"logontype=2|logontype=3|logontype=10|clientaddress|c0a83867|"
    r"readme|tools|service|cmd\.exe|powershell|psexec|winlogon|explorer)",
    re.I
)

def clean(v):
    return " ".join((v or "").replace("\r", " ").replace("\n", " ").split())

def trunc(v, n=900):
    v = clean(v)
    return v if len(v) <= n else v[:n] + "..."

def decode_client_addresses(summary):
    hits = []
    for m in re.finditer(r"ClientAddress=([0-9A-Fa-f]+)", summary):
        h = m.group(1)
        # sockaddr_in típico: 02 00 puerto puerto IPv4
        if len(h) >= 16 and h[:4].lower() == "0200":
            ip_hex = h[8:16]
            try:
                ip = ".".join(str(int(ip_hex[i:i+2], 16)) for i in range(0, 8, 2))
                hits.append(ip)
            except Exception:
                pass
    return ",".join(sorted(set(hits)))

with TSV.open("r", encoding="utf-8", newline="") as f:
    rows = list(csv.DictReader(f, delimiter="\t"))

selected = []
for r in rows:
    joined = " ".join(clean(v) for v in r.values())
    if r["EventID"] in KEY_EVENT_IDS and KEYWORDS.search(joined):
        selected.append(r)

selected.sort(key=lambda r: (r["TimeCreatedUTC"], r["LogFile"], r["EventRecordID"]))

lines = []
lines.append("TimeUTC\tLog\tRecord\tEventID\tProvider\tSubject\tTarget\tLogonType\tIP\tDecodedClientIP\tProcess\tSummary")

for r in selected:
    subject = "\\".join(x for x in [r["SubjectDomainName"], r["SubjectUserName"]] if x)
    target = "\\".join(x for x in [r["TargetDomainName"], r["TargetUserName"]] if x)
    summary = r["DataSummary"]
    decoded = decode_client_addresses(summary)

    lines.append(
        f'{r["TimeCreatedUTC"]}\t{r["LogFile"]}\t{r["EventRecordID"]}\t{r["EventID"]}\t'
        f'{r["Provider"]}\t{subject}\t{target}\t{r["LogonType"]}\t{r["IpAddress"]}\t'
        f'{decoded}\t{r["ProcessName"] or r["NewProcessName"]}\t{trunc(summary)}'
    )

OUT.write_text("\n".join(lines) + "\n", encoding="utf-8")
print(f"[OK] Timeline crítica escrita en: {OUT}")
print(f"[OK] Eventos seleccionados: {len(selected)}")
