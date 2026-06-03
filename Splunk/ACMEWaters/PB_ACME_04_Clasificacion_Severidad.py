# -*- coding: utf-8 -*-
"""
ACME WATERS · Splunk Phantom / Splunk SOAR
PB_ACME_04_Clasificacion_Severidad

Objetivo:
- Clasificar severidad inicial del evento/caso según evidencia de reputación.
- Para que sea autocontenido, consulta reputación del hash con VirusTotal v3.
- Usa el Asset: virustotal_acme_waters.
"""

import phantom.rules as phantom

PLAYBOOK_NAME = "PB_ACME_04_Clasificacion_Severidad"
VT_ASSET = "virustotal_acme_waters"


def _safe_int(value, default=0):
    try:
        return int(value)
    except Exception:
        return default


def _dedupe(values):
    result = []
    for value in values:
        if value is None:
            continue
        candidates = value if isinstance(value, list) else [value]
        for item in candidates:
            item = str(item).strip()
            if item and item not in result:
                result.append(item)
    return result


def _collect_file_hashes(container):
    rows = phantom.collect2(
        container=container,
        datapath=[
            "artifact:*.cef.fileHashSha256",
            "artifact:*.cef.fileHash",
            "artifact:*.cef.fileName",
            "artifact:*.id",
        ],
    )
    params, seen = [], set()
    for file_hash_sha256, file_hash, file_name, artifact_id in rows:
        for hash_value in _dedupe([file_hash_sha256, file_hash]):
            if hash_value in seen:
                continue
            seen.add(hash_value)
            params.append({"hash": hash_value, "context": {"artifact_id": artifact_id, "file_name": file_name}})
    return params


def _parse_vt_counters(results):
    max_malicious = 0
    max_suspicious = 0

    for result in results or []:
        summary = result.get("summary", {}) or {}
        malicious = _safe_int(summary.get("malicious", summary.get("malicious_count", 0)))
        suspicious = _safe_int(summary.get("suspicious", summary.get("suspicious_count", 0)))

        max_malicious = max(max_malicious, malicious)
        max_suspicious = max(max_suspicious, suspicious)

    return max_malicious, max_suspicious


def _set_case_severity(container, severity, reason):
    """
    Actualiza severidad en Phantom/SOAR si la API está disponible en la instancia.
    Si no fuera posible, deja la decisión documentada mediante nota.
    """
    try:
        phantom.set_severity(container=container, severity=severity)
    except Exception as exc:
        phantom.debug(f"{PLAYBOOK_NAME}: no se pudo modificar severidad automáticamente: {exc}")

    note_content = f"""### ACME WATERS · Clasificación de severidad

**Severidad propuesta:** `{severity}`  
**Motivo:** {reason}

Criterio aplicado:
- `High`: evidencia maliciosa en reputación de fichero/URL/dominio/IP.
- `Medium`: no hay confirmación maliciosa, pero el evento mantiene contexto sospechoso.
- `Low`: evento sin indicadores útiles o sin evidencias relevantes.
"""
    phantom.add_note(
        container=container,
        title=f"ACME WATERS · Severidad propuesta: {severity}",
        content=note_content,
        note_format="markdown",
        note_type="general",
    )


@phantom.playbook_block()
def on_start(container):
    phantom.debug(f"{PLAYBOOK_NAME}: on_start() called")

    params = _collect_file_hashes(container)
    if not params:
        _set_case_severity(
            container,
            "medium",
            "No se han encontrado hashes de fichero para consulta automática; mantener revisión manual.",
        )
        return

    phantom.act(
        "file reputation",
        parameters=params,
        assets=[VT_ASSET],
        name="file_reputation_for_classification",
        callback=file_reputation_for_classification_callback,
    )
    return


@phantom.playbook_block()
def file_reputation_for_classification_callback(action=None, success=None, container=None, results=None,
                                                handle=None, filtered_artifacts=None, filtered_results=None,
                                                custom_function=None):
    phantom.debug(f"{PLAYBOOK_NAME}: file_reputation_for_classification_callback() called")

    max_malicious, max_suspicious = _parse_vt_counters(results)
    phantom.save_run_data(key=f"{PLAYBOOK_NAME}:max_malicious", value=str(max_malicious))
    phantom.save_run_data(key=f"{PLAYBOOK_NAME}:max_suspicious", value=str(max_suspicious))

    if max_malicious > 0:
        _set_case_severity(
            container,
            "high",
            f"VirusTotal devuelve {max_malicious} detecciones maliciosas en al menos un indicador.",
        )
    elif max_suspicious > 0:
        _set_case_severity(
            container,
            "medium",
            f"VirusTotal devuelve {max_suspicious} detecciones sospechosas; requiere revisión manual.",
        )
    else:
        _set_case_severity(
            container,
            "medium",
            "No existen detecciones maliciosas ni sospechosas, pero el evento procede de correo con adjunto sospechoso.",
        )
    return


@phantom.playbook_block()
def on_finish(container, summary):
    phantom.debug(f"{PLAYBOOK_NAME}: on_finish() called")
    return
