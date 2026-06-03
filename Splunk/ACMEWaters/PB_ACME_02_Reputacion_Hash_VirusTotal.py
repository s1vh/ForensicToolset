# -*- coding: utf-8 -*-
"""
ACME WATERS · Splunk Phantom / Splunk SOAR
PB_ACME_02_Reputacion_Hash_VirusTotal

Objetivo:
- Consultar en VirusTotal v3 la reputación de hashes de fichero disponibles en el evento.
- Usa el Asset: virustotal_acme_waters.
- Acción esperada de VirusTotal v3: file reputation.
"""

import phantom.rules as phantom

PLAYBOOK_NAME = "PB_ACME_02_Reputacion_Hash_VirusTotal"
VT_ASSET = "virustotal_acme_waters"


def _dedupe(values):
    result = []
    for value in values:
        if value is None:
            continue
        value = str(value).strip()
        if value and value not in result:
            result.append(value)
    return result


def _safe_int(value, default=0):
    try:
        return int(value)
    except Exception:
        return default


def _extract_hash_parameters(container):
    rows = phantom.collect2(
        container=container,
        datapath=[
            "artifact:*.cef.fileHashSha256",
            "artifact:*.cef.fileHash",
            "artifact:*.cef.fileName",
            "artifact:*.id",
        ],
    )

    parameters = []
    seen = set()

    for file_hash_sha256, file_hash, file_name, artifact_id in rows:
        for hash_value in _dedupe([file_hash_sha256, file_hash]):
            if hash_value in seen:
                continue
            seen.add(hash_value)
            parameters.append({
                "hash": hash_value,
                "context": {
                    "artifact_id": artifact_id,
                    "file_name": file_name,
                },
            })

    return parameters


def _summarize_results(results):
    lines = []
    max_malicious = 0
    max_suspicious = 0

    for result in results or []:
        param = result.get("param", {}) or {}
        summary = result.get("summary", {}) or {}
        hash_value = param.get("hash", "N/D")

        malicious = _safe_int(summary.get("malicious", summary.get("malicious_count", 0)))
        suspicious = _safe_int(summary.get("suspicious", summary.get("suspicious_count", 0)))
        harmless = _safe_int(summary.get("harmless", summary.get("harmless_count", 0)))
        undetected = _safe_int(summary.get("undetected", summary.get("undetected_count", 0)))

        max_malicious = max(max_malicious, malicious)
        max_suspicious = max(max_suspicious, suspicious)

        lines.append(
            f"| `{hash_value}` | {harmless} | {malicious} | {suspicious} | {undetected} |"
        )

    return lines, max_malicious, max_suspicious


@phantom.playbook_block()
def on_start(container):
    phantom.debug(f"{PLAYBOOK_NAME}: on_start() called")
    parameters = _extract_hash_parameters(container)

    if not parameters:
        phantom.add_note(
            container=container,
            title="ACME WATERS · Reputación de hash no ejecutada",
            content="No se han encontrado campos `fileHashSha256` o `fileHash` en los artefactos del evento.",
            note_format="markdown",
            note_type="general",
        )
        return

    phantom.act(
        "file reputation",
        parameters=parameters,
        assets=[VT_ASSET],
        name="file_reputation_1",
        callback=file_reputation_1_callback,
    )
    return


@phantom.playbook_block()
def file_reputation_1_callback(action=None, success=None, container=None, results=None,
                               handle=None, filtered_artifacts=None, filtered_results=None,
                               custom_function=None):
    phantom.debug(f"{PLAYBOOK_NAME}: file_reputation_1_callback() called")

    lines, max_malicious, max_suspicious = _summarize_results(results)

    phantom.save_run_data(key=f"{PLAYBOOK_NAME}:max_malicious", value=str(max_malicious))
    phantom.save_run_data(key=f"{PLAYBOOK_NAME}:max_suspicious", value=str(max_suspicious))

    table = "\n".join(lines) if lines else "| N/D | 0 | 0 | 0 | 0 |"
    note_content = f"""### ACME WATERS · Resultado de reputación de hash en VirusTotal

| Hash | Harmless | Malicious | Suspicious | Undetected |
|---|---:|---:|---:|---:|
{table}

**Interpretación inicial:**  
- `Malicious > 0`: evidencia de contenido dañino y posible escalado.
- `Suspicious > 0`: revisar manualmente y mantener trazabilidad.
- `Malicious = 0` no garantiza legitimidad del fichero.
"""

    phantom.add_note(
        container=container,
        title="ACME WATERS · Resultado VirusTotal file reputation",
        content=note_content,
        note_format="markdown",
        note_type="general",
    )
    return


@phantom.playbook_block()
def on_finish(container, summary):
    phantom.debug(f"{PLAYBOOK_NAME}: on_finish() called")
    return
