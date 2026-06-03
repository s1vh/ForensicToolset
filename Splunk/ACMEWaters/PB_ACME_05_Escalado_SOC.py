# -*- coding: utf-8 -*-
"""
ACME WATERS · Splunk Phantom / Splunk SOAR
PB_ACME_05_Escalado_SOC

Objetivo:
- Documentar decisión de escalado al SOC a partir de la severidad y contexto del caso.
- No cierra ni resuelve automáticamente el caso: el cierre queda en manos del analista.
"""

import phantom.rules as phantom

PLAYBOOK_NAME = "PB_ACME_05_Escalado_SOC"


def _get_container_value(container, key, default=None):
    try:
        return container.get(key, default)
    except Exception:
        return default


def _collect_basic_context(container):
    rows = phantom.collect2(
        container=container,
        datapath=[
            "artifact:*.cef.fileName",
            "artifact:*.cef.fileHashSha256",
            "artifact:*.cef.fileHash",
            "artifact:*.cef.requestURL",
            "artifact:*.cef.url",
            "artifact:*.id",
        ],
    )

    filenames, hashes, urls, artifact_ids = [], [], [], []
    for file_name, sha256, file_hash, request_url, url, artifact_id in rows:
        for value, target in [
            (file_name, filenames),
            (sha256, hashes),
            (file_hash, hashes),
            (request_url, urls),
            (url, urls),
            (artifact_id, artifact_ids),
        ]:
            if value is None:
                continue
            value = str(value).strip()
            if value and value not in target:
                target.append(value)

    return {
        "filenames": filenames,
        "hashes": hashes,
        "urls": urls,
        "artifact_ids": artifact_ids,
    }


def _fmt(values):
    return ", ".join(values) if values else "No identificado"


@phantom.playbook_block()
def on_start(container):
    phantom.debug(f"{PLAYBOOK_NAME}: on_start() called")

    severity = str(_get_container_value(container, "severity", "unknown")).lower()
    label = _get_container_value(container, "label", "unknown")
    name = _get_container_value(container, "name", "unknown")
    container_id = _get_container_value(container, "id", "unknown")
    context = _collect_basic_context(container)

    should_escalate = severity in ("high", "critical")

    decision = (
        "Escalado SOC recomendado/registrado por severidad alta o crítica."
        if should_escalate
        else "No se registra escalado automático por severidad; mantener trazabilidad y revisión según Workbook."
    )

    note_content = f"""### ACME WATERS · Decisión de escalado SOC

| Campo | Valor |
|---|---|
| Container ID | {container_id} |
| Nombre del evento/caso | {name} |
| Label | {label} |
| Severidad actual | {severity} |
| Artefactos | {_fmt(context["artifact_ids"])} |
| Ficheros | {_fmt(context["filenames"])} |
| Hashes | {_fmt(context["hashes"])} |
| URLs | {_fmt(context["urls"])} |
| Decisión | {decision} |

**Criterios de escalado usados:** indicador malicioso confirmado, ejecución confirmada, múltiples usuarios afectados, credenciales comprometidas, indicios de propagación o severidad `High`.
"""

    phantom.add_note(
        container=container,
        title="ACME WATERS · Escalado SOC",
        content=note_content,
        note_format="markdown",
        note_type="general",
    )

    return


@phantom.playbook_block()
def on_finish(container, summary):
    phantom.debug(f"{PLAYBOOK_NAME}: on_finish() called")
    return
