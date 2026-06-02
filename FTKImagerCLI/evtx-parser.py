from pathlib import Path
from Evtx.Evtx import Evtx
import xml.etree.ElementTree as ET
import csv
import re

EVTX_DIR = Path.home() / "forense_challenge02" / "export" / "evtx"
OUT_DIR = Path.home() / "forense_challenge02" / "parsed_evtx"
OUT_DIR.mkdir(parents=True, exist_ok=True)

ALL_TSV = OUT_DIR / "events_all.tsv"
WINDOW_TSV = OUT_DIR / "events_2015-12-12_0300-0330Z.tsv"
SUSP_TSV = OUT_DIR / "events_2015-12-12_0300-0330Z_relevantes.tsv"
ERRORS = OUT_DIR / "parse_errors.txt"

START = "2015-12-12T03:00:00"
END   = "2015-12-12T03:30:00"

INTERESTING_IDS = {
    # Security
    "4624", "4625", "4634", "4647", "4672", "4688",
    "4720", "4722", "4723", "4724", "4728", "4732", "4738",
    "4776",
    # System
    "7036", "7040", "7045", "6005", "6006", "6008", "1074",
    # Terminal Services
    "21", "22", "23", "24", "25", "39", "40", "41", "42",
    # PowerShell
    "400", "403", "600", "800", "4103", "4104",
    # Task Scheduler
    "106", "140", "141", "200", "201",
}

KEYWORDS = re.compile(
    r"(master|admin|administrator|remote|rdp|terminal|smb|powershell|cmd\.exe|"
    r"net\.exe|net1\.exe|notepad|logon|logoff|special privileges|service|task|"
    r"127\.0\.0\.1|192\.168|10\.|172\.)",
    re.IGNORECASE
)

def local_name(tag):
    return tag.split("}", 1)[-1] if "}" in tag else tag

def first_text(root, wanted_name):
    for elem in root.iter():
        if local_name(elem.tag) == wanted_name:
            return (elem.text or "").strip()
    return ""

def system_attr(root, elem_name, attr_name):
    for elem in root.iter():
        if local_name(elem.tag) == elem_name:
            return elem.attrib.get(attr_name, "")
    return ""

def event_data(root):
    data = {}
    for elem in root.iter():
        if local_name(elem.tag) == "Data":
            name = elem.attrib.get("Name", "")
            value = (elem.text or "").strip()
            if name:
                data[name] = value
    return data

def userdata_flat(root):
    data = {}
    for elem in root.iter():
        lname = local_name(elem.tag)
        if lname not in {"Event", "System", "EventData", "UserData"}:
            text = (elem.text or "").strip()
            if text and lname not in data:
                data[lname] = text
    return data

def get_record_number(record):
    try:
        return str(record.record_num())
    except Exception:
        return ""

fields = [
    "LogFile", "RecordNumber", "TimeCreatedUTC", "EventID", "Provider",
    "Channel", "Computer", "SecurityUserID",
    "SubjectUserName", "SubjectDomainName",
    "TargetUserName", "TargetDomainName",
    "LogonType", "LogonProcessName", "AuthenticationPackageName",
    "IpAddress", "IpPort", "WorkstationName",
    "ProcessName", "NewProcessName", "CommandLine",
    "ServiceName", "ServiceFileName",
    "TaskName", "Status", "SubStatus",
    "MessageFields"
]

all_rows = []
window_rows = []
susp_rows = []
errors = []

for evtx_path in sorted(EVTX_DIR.glob("*.evtx")):
    try:
        with Evtx(str(evtx_path)) as log:
            for record in log.records():
                try:
                    xml = record.xml()
                    root = ET.fromstring(xml)

                    ed = event_data(root)
                    ud = userdata_flat(root)

                    event_id = first_text(root, "EventID")
                    provider = system_attr(root, "Provider", "Name")
                    time_created = system_attr(root, "TimeCreated", "SystemTime")
                    channel = first_text(root, "Channel")
                    computer = first_text(root, "Computer")
                    security_user = system_attr(root, "Security", "UserID")

                    merged = {}
                    merged.update(ud)
                    merged.update(ed)

                    row = {
                        "LogFile": evtx_path.name,
                        "RecordNumber": get_record_number(record),
                        "TimeCreatedUTC": time_created,
                        "EventID": event_id,
                        "Provider": provider,
                        "Channel": channel,
                        "Computer": computer,
                        "SecurityUserID": security_user,
                        "SubjectUserName": merged.get("SubjectUserName", ""),
                        "SubjectDomainName": merged.get("SubjectDomainName", ""),
                        "TargetUserName": merged.get("TargetUserName", ""),
                        "TargetDomainName": merged.get("TargetDomainName", ""),
                        "LogonType": merged.get("LogonType", ""),
                        "LogonProcessName": merged.get("LogonProcessName", ""),
                        "AuthenticationPackageName": merged.get("AuthenticationPackageName", ""),
                        "IpAddress": merged.get("IpAddress", ""),
                        "IpPort": merged.get("IpPort", ""),
                        "WorkstationName": merged.get("WorkstationName", ""),
                        "ProcessName": merged.get("ProcessName", ""),
                        "NewProcessName": merged.get("NewProcessName", ""),
                        "CommandLine": merged.get("CommandLine", ""),
                        "ServiceName": merged.get("ServiceName", ""),
                        "ServiceFileName": merged.get("ServiceFileName", ""),
                        "TaskName": merged.get("TaskName", ""),
                        "Status": merged.get("Status", ""),
                        "SubStatus": merged.get("SubStatus", ""),
                        "MessageFields": " | ".join(
                            f"{k}={v}" for k, v in sorted(merged.items())
                            if v and k not in {
                                "SubjectUserName", "SubjectDomainName",
                                "TargetUserName", "TargetDomainName",
                                "LogonType", "LogonProcessName",
                                "AuthenticationPackageName", "IpAddress",
                                "IpPort", "WorkstationName", "ProcessName",
                                "NewProcessName", "CommandLine",
                                "ServiceName", "ServiceFileName", "TaskName",
                                "Status", "SubStatus"
                            }
                        )
                    }

                    all_rows.append(row)

                    # Comparación ISO aproximada: todas están en Z.
                    t = time_created.replace("Z", "")
                    if START <= t < END:
                        window_rows.append(row)
                        joined = "\t".join(row.values())
                        if event_id in INTERESTING_IDS or KEYWORDS.search(joined):
                            susp_rows.append(row)

                except Exception as e:
                    errors.append(f"{evtx_path.name}: record parse error: {e}")
    except Exception as e:
        errors.append(f"{evtx_path.name}: file open error: {e}")

def write_tsv(path, rows):
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fields, delimiter="\t", extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)

write_tsv(ALL_TSV, all_rows)
write_tsv(WINDOW_TSV, window_rows)
write_tsv(SUSP_TSV, susp_rows)

ERRORS.write_text("\n".join(errors), encoding="utf-8")

print(f"[OK] Eventos totales: {len(all_rows)}")
print(f"[OK] Eventos ventana 03:00-03:30Z: {len(window_rows)}")
print(f"[OK] Eventos relevantes ventana: {len(susp_rows)}")
print(f"[OK] Salida: {OUT_DIR}")
print(f"[OK] Errores: {len(errors)}")
PY
