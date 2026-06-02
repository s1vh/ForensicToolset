from pathlib import Path
import csv

BASE = Path.home() / "forense_challenge02"
TSV = BASE / "parsed_evtx" / "tsv" / "events_window_2015-12-12_0300-0330Z.tsv"
OUT = BASE / "logs" / "92_account_management_admin_master.txt"

EVENTS = {
    "4624", "4625", "4634", "4647", "4648", "4672",
    "4720", "4722", "4723", "4724", "4725",
    "4728", "4732", "4733", "4738", "4776"
}

KEYS = ("administrator", "master", "admins", "administrators", "builtin", "sensei")

def clean(v):
    return " ".join((v or "").replace("\r", " ").replace("\n", " ").split())

def trunc(v, n=1200):
    v = clean(v)
    return v if len(v) <= n else v[:n] + "..."

with TSV.open("r", encoding="utf-8", newline="") as f:
    rows = list(csv.DictReader(f, delimiter="\t"))

selected = []

for r in rows:
    if "Security" not in r["LogFile"]:
        continue

    joined = " ".join(clean(v) for v in r.values()).lower()

    if r["EventID"] in EVENTS and any(k in joined for k in KEYS):
        selected.append(r)

selected.sort(key=lambda r: (r["TimeCreatedUTC"], int(r["EventRecordID"] or 0)))

lines = []
lines.append(
    "TimeUTC\tRecord\tEventID\tSubjectDomain\tSubjectUser\tTargetDomain\tTargetUser\t"
    "LogonType\tAuthPkg\tIpAddress\tWorkstation\tProcessName\tSummary"
)

for r in selected:
    lines.append(
        f'{r["TimeCreatedUTC"]}\t'
        f'{r["EventRecordID"]}\t'
        f'{r["EventID"]}\t'
        f'{r["SubjectDomainName"]}\t'
        f'{r["SubjectUserName"]}\t'
        f'{r["TargetDomainName"]}\t'
        f'{r["TargetUserName"]}\t'
        f'{r["LogonType"]}\t'
        f'{r["AuthenticationPackageName"]}\t'
        f'{r["IpAddress"]}\t'
        f'{r["WorkstationName"]}\t'
        f'{r["ProcessName"]}\t'
        f'{trunc(r["DataSummary"])}'
    )

OUT.write_text("\n".join(lines) + "\n", encoding="utf-8")

print(f"[OK] Escrito: {OUT}")
print(f"[OK] Eventos seleccionados: {len(selected)}")
