from pathlib import Path
import xml.etree.ElementTree as ET
import csv
import re

XML_DIR = Path.home() / "forense_challenge02" / "parsed_evtx" / "xml"
OUT_DIR = Path.home() / "forense_challenge02" / "parsed_evtx" / "tsv"
LOG_DIR = Path.home() / "forense_challenge02" / "logs"
OUT_DIR.mkdir(parents=True, exist_ok=True)
LOG_DIR.mkdir(parents=True, exist_ok=True)

START = "2015-12-12T03:00:00"
END   = "2015-12-12T03:30:00"

INTERESTING_IDS = {
    "4624", "4625", "4634", "4647", "4672", "4688",
    "4720", "4722", "4723", "4724", "4728", "4732", "4738", "4776",
    "6005", "6006", "6008", "7036", "7040", "7045",
    "21", "22", "23", "24", "25", "39", "40", "41", "42",
    "400", "403", "600", "800", "4103", "4104",
    "106", "140", "141", "200", "201",
    "1", "2", "3", "4", "5", "6"
}

KEYWORDS = re.compile(
    r"(master|administrator|admin|rdp|remote|terminal|smb|powershell|cmd\.exe|"
    r"net\.exe|net1\.exe|notepad|service|logon|special privileges|profile|"
    r"192\.168\.|10\.|172\.)",
    re.IGNORECASE
)

FIELDS = [
    "LogFile", "TimeCreatedUTC", "EventRecordID", "EventID", "Provider",
    "Channel", "Computer", "SecurityUserID",
    "SubjectUserName", "SubjectDomainName",
    "TargetUserName", "TargetDomainName",
    "LogonType", "LogonProcessName", "AuthenticationPackageName",
    "IpAddress", "IpPort", "WorkstationName",
    "ProcessName", "NewProcessName", "CommandLine",
    "ServiceName", "ServiceFileName",
    "TaskName", "User", "SessionID", "Address",
    "Param1", "Param2", "DataSummary"
]

def lname(tag):
    return tag.split("}", 1)[-1] if "}" in tag else tag

def find_text(root, name):
    for e in root.iter():
        if lname(e.tag) == name:
            return (e.text or "").strip()
    return ""

def find_attr(root, name, attr):
    for e in root.iter():
        if lname(e.tag) == name:
            return e.attrib.get(attr, "")
    return ""

def flatten_data(root):
    data = {}
    unnamed = 0

    for e in root.iter():
        tag = lname(e.tag)

        if tag == "Data":
            key = e.attrib.get("Name")
            if not key:
                key = f"Data{unnamed}"
                unnamed += 1
            data[key] = (e.text or "").strip()

        elif tag not in {
            "Event", "System", "EventData", "UserData", "Execution",
            "Correlation", "Provider", "TimeCreated", "Security",
            "Version", "Level", "Task", "Opcode", "Keywords",
            "EventID", "EventRecordID", "Channel", "Computer"
        }:
            txt = (e.text or "").strip()
            if txt:
                if tag in data:
                    i = 2
                    while f"{tag}_{i}" in data:
                        i += 1
                    data[f"{tag}_{i}"] = txt
                else:
                    data[tag] = txt

    return data

def extract_event_blocks(text):
    # evtxexport puede generar varios <Event>...</Event> seguidos sin raíz XML única.
    return re.findall(r'<Event\b.*?</Event>', text, flags=re.DOTALL)

def iter_events(xml_path):
    text = xml_path.read_text(errors="ignore")

    blocks = extract_event_blocks(text)
    events = []

    for block in blocks:
        try:
            events.append(ET.fromstring(block))
        except ET.ParseError:
            continue

    return events

def make_row(xml_path, ev):
    data = flatten_data(ev)

    event_id = find_text(ev, "EventID")
    time = find_attr(ev, "TimeCreated", "SystemTime")

    summary = " | ".join(
        f"{k}={v}" for k, v in sorted(data.items())
        if v
    )

    return {
        "LogFile": xml_path.name,
        "TimeCreatedUTC": time,
        "EventRecordID": find_text(ev, "EventRecordID"),
        "EventID": event_id,
        "Provider": find_attr(ev, "Provider", "Name"),
        "Channel": find_text(ev, "Channel"),
        "Computer": find_text(ev, "Computer"),
        "SecurityUserID": find_attr(ev, "Security", "UserID"),
        "SubjectUserName": data.get("SubjectUserName", ""),
        "SubjectDomainName": data.get("SubjectDomainName", ""),
        "TargetUserName": data.get("TargetUserName", ""),
        "TargetDomainName": data.get("TargetDomainName", ""),
        "LogonType": data.get("LogonType", ""),
        "LogonProcessName": data.get("LogonProcessName", ""),
        "AuthenticationPackageName": data.get("AuthenticationPackageName", ""),
        "IpAddress": data.get("IpAddress", ""),
        "IpPort": data.get("IpPort", ""),
        "WorkstationName": data.get("WorkstationName", ""),
        "ProcessName": data.get("ProcessName", ""),
        "NewProcessName": data.get("NewProcessName", ""),
        "CommandLine": data.get("CommandLine", ""),
        "ServiceName": data.get("ServiceName", ""),
        "ServiceFileName": data.get("ServiceFileName", ""),
        "TaskName": data.get("TaskName", ""),
        "User": data.get("User", "") or data.get("UserName", ""),
        "SessionID": data.get("SessionID", "") or data.get("SessionId", ""),
        "Address": data.get("Address", "") or data.get("SourceAddress", ""),
        "Param1": data.get("param1", "") or data.get("Param1", ""),
        "Param2": data.get("param2", "") or data.get("Param2", ""),
        "DataSummary": summary
    }

all_rows = []
window_rows = []
interesting_rows = []
debug_lines = []

for xml_path in sorted(XML_DIR.glob("*.xml")):
    events = iter_events(xml_path)
    debug_lines.append(f"{xml_path.name}: {len(events)} eventos")

    for ev in events:
        row = make_row(xml_path, ev)
        all_rows.append(row)

        t = row["TimeCreatedUTC"].replace("Z", "")
        if START <= t < END:
            window_rows.append(row)

            joined = "\t".join(row.get(f, "") for f in FIELDS)
            if row["EventID"] in INTERESTING_IDS or KEYWORDS.search(joined):
                interesting_rows.append(row)

def write_tsv(path, rows):
    with path.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=FIELDS, delimiter="\t", extrasaction="ignore")
        w.writeheader()
        w.writerows(rows)

write_tsv(OUT_DIR / "events_all.tsv", all_rows)
write_tsv(OUT_DIR / "events_window_2015-12-12_0300-0330Z.tsv", window_rows)
write_tsv(OUT_DIR / "events_interesting_2015-12-12_0300-0330Z.tsv", interesting_rows)

(LOG_DIR / "59_evtx_parser_debug.txt").write_text("\n".join(debug_lines), encoding="utf-8")

print(f"[OK] Eventos totales: {len(all_rows)}")
print(f"[OK] Eventos en ventana: {len(window_rows)}")
print(f"[OK] Eventos interesantes en ventana: {len(interesting_rows)}")
print(f"[OK] Salida: {OUT_DIR}")
print(f"[OK] Debug: {LOG_DIR / '59_evtx_parser_debug.txt'}")
PY
