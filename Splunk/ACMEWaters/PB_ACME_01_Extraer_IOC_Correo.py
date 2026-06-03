# -*- coding: utf-8 -*-
"""
ACME WATERS · Splunk Phantom / Splunk SOAR
PB_ACME_01_Extraer_IOC_Correo

Objetivo:
- Extraer y documentar indicadores iniciales desde un correo sospechoso.
- Registrar hashes, ficheros, URLs, dominios, IPs y metadatos básicos de correo.
- No ejecuta acciones externas: prepara la información para los playbooks de reputación.

Notas:
- Pensado para pegar/importar en el editor Python de Playbooks de Splunk SOAR.
- Validar datapaths CEF exactos si los eventos del profesor usan nombres distintos.
"""

import json
import phantom.rules as phantom

PLAYBOOK_NAME = "PB_ACME_01_Extraer_IOC_Correo"


def _normalize_value(value):
    if value is None:
        return None
    if isinstance(value, list):
        return [str(item).strip() for item in value if item not in (None, "")]
    value = str(value).strip()
    return value or None


def _extend_unique(target, value):
    value = _normalize_value(value)
    if value is None:
        return
    values = value if isinstance(value, list) else [value]
    for item in values:
        if item and item not in target:
            target.append(item)


def _collect_email_iocs(container):
    """Extrae IOCs desde artefactos de correo/fichero usando datapaths CEF comunes."""
    datapaths = [
        "artifact:*.cef.fileHashSha256",
        "artifact:*.cef.fileHash",
        "artifact:*.cef.fileName",
        "artifact:*.cef.requestURL",
        "artifact:*.cef.url",
        "artifact:*.cef.destinationDnsDomain",
        "artifact:*.cef.domain",
        "artifact:*.cef.destinationAddress",
        "artifact:*.cef.sourceAddress",
        "artifact:*.cef.emailHeaders",
        "artifact:*.cef.emailSubject",
        "artifact:*.cef.emailFrom",
        "artifact:*.cef.emailTo",
        "artifact:*.id",
    ]

    rows = phantom.collect2(container=container, datapath=datapaths)

    iocs = {
        "hashes": [],
        "filenames": [],
        "urls": [],
        "domains": [],
        "ips": [],
        "subjects": [],
        "senders": [],
        "recipients": [],
        "headers_present": False,
        "artifact_ids": [],
    }

    for row in rows:
        (
            file_hash_sha256,
            file_hash,
            file_name,
            request_url,
            url,
            destination_domain,
            domain,
            destination_ip,
            source_ip,
            headers,
            subject,
            sender,
            recipient,
            artifact_id,
        ) = row

        _extend_unique(iocs["hashes"], file_hash_sha256)
        _extend_unique(iocs["hashes"], file_hash)
        _extend_unique(iocs["filenames"], file_name)
        _extend_unique(iocs["urls"], request_url)
        _extend_unique(iocs["urls"], url)
        _extend_unique(iocs["domains"], destination_domain)
        _extend_unique(iocs["domains"], domain)
        _extend_unique(iocs["ips"], destination_ip)
        _extend_unique(iocs["ips"], source_ip)
        _extend_unique(iocs["subjects"], subject)
        _extend_unique(iocs["senders"], sender)
        _extend_unique(iocs["recipients"], recipient)
        _extend_unique(iocs["artifact_ids"], artifact_id)

        if headers:
            iocs["headers_present"] = True

    return iocs


def _render_ioc_note(iocs):
    def fmt(values):
        return ", ".join(values) if values else "No identificado"

    return f"""### ACME WATERS · Extracción inicial de IOCs

**Playbook:** `{PLAYBOOK_NAME}`  
**Objetivo:** registrar indicadores de compromiso desde un correo sospechoso.

| Tipo de dato | Valor |
|---|---|
| Artefactos analizados | {fmt(iocs["artifact_ids"])} |
| Ficheros adjuntos | {fmt(iocs["filenames"])} |
| Hashes disponibles | {fmt(iocs["hashes"])} |
| URLs | {fmt(iocs["urls"])} |
| Dominios | {fmt(iocs["domains"])} |
| Direcciones IP | {fmt(iocs["ips"])} |
| Remitentes | {fmt(iocs["senders"])} |
| Destinatarios | {fmt(iocs["recipients"])} |
| Asuntos | {fmt(iocs["subjects"])} |
| Cabeceras presentes | {"Sí" if iocs["headers_present"] else "No"} |

**Siguiente fase recomendada:** ejecutar reputación de hash con VirusTotal si existe SHA-256, y reputación de URL/dominio/IP si esos indicadores están presentes.
"""


@phantom.playbook_block()
def on_start(container):
    phantom.debug(f"{PLAYBOOK_NAME}: on_start() called")

    iocs = _collect_email_iocs(container)
    phantom.save_run_data(key=f"{PLAYBOOK_NAME}:iocs", value=json.dumps(iocs, ensure_ascii=False))

    phantom.add_note(
        container=container,
        title="ACME WATERS · IOCs extraídos del correo sospechoso",
        content=_render_ioc_note(iocs),
        note_format="markdown",
        note_type="general",
    )

    phantom.debug(f"{PLAYBOOK_NAME}: IOCs extraídos: {json.dumps(iocs, ensure_ascii=False)}")
    return


@phantom.playbook_block()
def on_finish(container, summary):
    phantom.debug(f"{PLAYBOOK_NAME}: on_finish() called")
    return
