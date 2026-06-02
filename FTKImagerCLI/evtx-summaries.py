from pathlib import Path
import csv
from collections import Counter, defaultdict

BASE = Path.home() / "forense_challenge02"
TSV = BASE / "parsed_evtx" / "tsv" / "events_window_2015-12-12_0300-0330Z.tsv"
LOG = BASE / "logs"

def clean(v):
    if v is None:
        return ""
    return " ".join(str(v).replace("\r", " ").replace("\n", " ").split())

def trunc(v, n=220):
    v = clean(v)
    return v if len(v) <= n else v[:n] + "..."

with TSV.open("r", encoding="utf-8", newline="") as f:
    rows = list(csv.DictReader(f, delimiter="\t"))

def write(name, lines):
    path = LOG / name
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"[OK] {path}")

# 1. Conteo real
lines = []
lines.append(f"Eventos reales en ventana: {len(rows)}")
lines.append("")
lines.append("Eventos por log:")
for log, count in Counter(r["LogFile"] for r in rows).most_common():
    lines.append(f"{count:5d}  {log}")
write("66_evtx_conteo_real.txt", lines)

# 2. Conteo por EventID
counter = Counter((r["LogFile"], r["EventID"], r["Provider"]) for r in rows)
lines = ["count\tLogFile\tEventID\tProvider"]
for (log, eid, provider), count in counter.most_common():
    lines.append(f"{count}\t{log}\t{eid}\t{provider}")
write("67_evtx_eventid_counts.txt", lines)

# 3. Security: autenticación y privilegios
security_ids = {"4624", "4625", "4634", "4647", "4672", "4776", "4720", "4722", "4723", "4724", "4728", "4732", "4738"}
lines = [
    "TimeUTC\tRecord\tEventID\tSubject\tTarget\tLogonType\tAuthPkg\tIpAddress\tWorkstation\tProcess\tSummary"
]
for r in rows:
    if "Security" in r["LogFile"] and r["EventID"] in security_ids:
        subject = "\\".join(x for x in [r["SubjectDomainName"], r["SubjectUserName"]] if x)
        target = "\\".join(x for x in [r["TargetDomainName"], r["TargetUserName"]] if x)
        lines.append(
            f'{r["TimeCreatedUTC"]}\t{r["EventRecordID"]}\t{r["EventID"]}\t'
            f'{subject}\t{target}\t{r["LogonType"]}\t{r["AuthenticationPackageName"]}\t'
            f'{r["IpAddress"]}\t{r["WorkstationName"]}\t{r["ProcessName"]}\t{trunc(r["DataSummary"])}'
        )
write("68_security_logons_privilegios.txt", lines)

# 4. Terminal Services
lines = [
    "TimeUTC\tRecord\tEventID\tProvider\tUser\tSessionID\tAddress\tParam1\tParam2\tSummary"
]
for r in rows:
    if "TerminalServices" in r["LogFile"]:
        lines.append(
            f'{r["TimeCreatedUTC"]}\t{r["EventRecordID"]}\t{r["EventID"]}\t{r["Provider"]}\t'
            f'{r["User"]}\t{r["SessionID"]}\t{r["Address"]}\t{r["Param1"]}\t{r["Param2"]}\t{trunc(r["DataSummary"])}'
        )
write("69_terminalservices.txt", lines)

# 5. System: arranque, servicios, cambios de servicios
system_ids = {"6005", "6006", "6008", "7036", "7040", "7045", "1074"}
lines = [
    "TimeUTC\tRecord\tEventID\tProvider\tServiceName\tServiceFileName\tParam1\tParam2\tSummary"
]
for r in rows:
    if "System" in r["LogFile"] and r["EventID"] in system_ids:
        lines.append(
            f'{r["TimeCreatedUTC"]}\t{r["EventRecordID"]}\t{r["EventID"]}\t{r["Provider"]}\t'
            f'{r["ServiceName"]}\t{r["ServiceFileName"]}\t{r["Param1"]}\t{r["Param2"]}\t{trunc(r["DataSummary"])}'
        )
write("70_system_servicios.txt", lines)

# 6. SMB Server
lines = [
    "TimeUTC\tRecord\tEventID\tProvider\tUser\tAddress\tParam1\tParam2\tSummary"
]
for r in rows:
    if "SMBServer" in r["LogFile"]:
        lines.append(
            f'{r["TimeCreatedUTC"]}\t{r["EventRecordID"]}\t{r["EventID"]}\t{r["Provider"]}\t'
            f'{r["User"]}\t{r["Address"]}\t{r["Param1"]}\t{r["Param2"]}\t{trunc(r["DataSummary"])}'
        )
write("71_smbserver.txt", lines)

# 7. User Profile Service
lines = [
    "TimeUTC\tRecord\tEventID\tProvider\tUser\tParam1\tParam2\tSummary"
]
for r in rows:
    if "User_Profile" in r["LogFile"]:
        lines.append(
            f'{r["TimeCreatedUTC"]}\t{r["EventRecordID"]}\t{r["EventID"]}\t{r["Provider"]}\t'
            f'{r["User"]}\t{r["Param1"]}\t{r["Param2"]}\t{trunc(r["DataSummary"])}'
        )
write("72_userprofile.txt", lines)

# 8. Eventos que mencionan actores o acceso remoto
keywords = ("master", "administrator", "admin", "remote", "terminal", "rdp", "smb", "logon", "special privileges", "profile")
lines = [
    "TimeUTC\tLogFile\tRecord\tEventID\tProvider\tSummary"
]
for r in rows:
    joined = " ".join(clean(r.get(k, "")) for k in r.keys()).lower()
    if any(k in joined for k in keywords):
        lines.append(
            f'{r["TimeCreatedUTC"]}\t{r["LogFile"]}\t{r["EventRecordID"]}\t{r["EventID"]}\t'
            f'{r["Provider"]}\t{trunc(r["DataSummary"], 300)}'
        )
write("73_keyword_hits.txt", lines)
