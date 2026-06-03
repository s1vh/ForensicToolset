# -*- coding: utf-8 -*-
"""
ACME WATERS · Splunk Phantom / Splunk SOAR
PB_ACME_03_Reputacion_URL_Dominio

Objetivo:
- Consultar reputación de URLs, dominios e IPs presentes en el evento.
- Usa el Asset: virustotal_acme_waters.
- Acciones esperadas de VirusTotal v3: url reputation, domain reputation, ip reputation.
"""

import json
import phantom.rules as phantom

PLAYBOOK_NAME = "PB_ACME_03_Reputacion_URL_Dominio"
VT_ASSET = "virustotal_acme_waters"


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


def _collect_parameters(container):
    rows = phantom.collect2(
        container=container,
        datapath=[
            "artifact:*.cef.requestURL",
            "artifact:*.cef.url",
            "artifact:*.cef.destinationDnsDomain",
            "artifact:*.cef.domain",
            "artifact:*.cef.destinationAddress",
            "artifact:*.cef.sourceAddress",
            "artifact:*.id",
        ],
    )

    urls, domains, ips = [], [], []

    for request_url, url, destination_domain, domain, destination_ip, source_ip, artifact_id in rows:
        for value in _dedupe([request_url, url]):
            urls.append({"url": value, "context": {"artifact_id": artifact_id}})
        for value in _dedupe([destination_domain, domain]):
            domains.append({"domain": value, "context": {"artifact_id": artifact_id}})
        for value in _dedupe([destination_ip, source_ip]):
            ips.append({"ip": value, "context": {"artifact_id": artifact_id}})

    def dedupe_params(params, key):
        out, seen = [], set()
        for item in params:
            value = item.get(key)
            if value and value not in seen:
                seen.add(value)
                out.append(item)
        return out

    return {
        "urls": dedupe_params(urls, "url"),
        "domains": dedupe_params(domains, "domain"),
        "ips": dedupe_params(ips, "ip"),
    }


def _add_no_ioc_note(container):
    phantom.add_note(
        container=container,
        title="ACME WATERS · Reputación URL/dominio/IP no ejecutada",
        content=(
            "No se han encontrado URLs, dominios o direcciones IP en los artefactos del evento. "
            "La fase se documenta como no aplicable."
        ),
        note_format="markdown",
        note_type="general",
    )


def _finish_summary(container):
    url_count = phantom.get_run_data(key=f"{PLAYBOOK_NAME}:url_count") or "0"
    domain_count = phantom.get_run_data(key=f"{PLAYBOOK_NAME}:domain_count") or "0"
    ip_count = phantom.get_run_data(key=f"{PLAYBOOK_NAME}:ip_count") or "0"
    note_content = f"""### ACME WATERS · Reputación URL/dominio/IP finalizada

| Tipo | Indicadores procesados |
|---|---:|
| URLs | {url_count} |
| Dominios | {domain_count} |
| IPs | {ip_count} |

Revisar la vista **Activity** del evento para consultar las respuestas de VirusTotal.
"""
    phantom.add_note(
        container=container,
        title="ACME WATERS · Reputación URL/dominio/IP completada",
        content=note_content,
        note_format="markdown",
        note_type="general",
    )


def _run_domain_reputation(container, domains):
    if not domains:
        ips = json.loads(phantom.get_run_data(key=f"{PLAYBOOK_NAME}:ips") or "[]")
        _run_ip_reputation(container, ips)
        return

    phantom.act(
        "domain reputation",
        parameters=domains,
        assets=[VT_ASSET],
        name="domain_reputation_1",
        callback=domain_reputation_1_callback,
    )


def _run_ip_reputation(container, ips):
    if not ips:
        _finish_summary(container)
        return

    phantom.act(
        "ip reputation",
        parameters=ips,
        assets=[VT_ASSET],
        name="ip_reputation_1",
        callback=ip_reputation_1_callback,
    )


@phantom.playbook_block()
def on_start(container):
    phantom.debug(f"{PLAYBOOK_NAME}: on_start() called")
    collected = _collect_parameters(container)

    urls = collected["urls"]
    domains = collected["domains"]
    ips = collected["ips"]

    phantom.save_run_data(key=f"{PLAYBOOK_NAME}:url_count", value=str(len(urls)))
    phantom.save_run_data(key=f"{PLAYBOOK_NAME}:domain_count", value=str(len(domains)))
    phantom.save_run_data(key=f"{PLAYBOOK_NAME}:ip_count", value=str(len(ips)))
    phantom.save_run_data(key=f"{PLAYBOOK_NAME}:domains", value=json.dumps(domains))
    phantom.save_run_data(key=f"{PLAYBOOK_NAME}:ips", value=json.dumps(ips))

    if not urls and not domains and not ips:
        _add_no_ioc_note(container)
        return

    if urls:
        phantom.act(
            "url reputation",
            parameters=urls,
            assets=[VT_ASSET],
            name="url_reputation_1",
            callback=url_reputation_1_callback,
        )
    else:
        _run_domain_reputation(container, domains)
    return


@phantom.playbook_block()
def url_reputation_1_callback(action=None, success=None, container=None, results=None,
                              handle=None, filtered_artifacts=None, filtered_results=None,
                              custom_function=None):
    phantom.debug(f"{PLAYBOOK_NAME}: url_reputation_1_callback() called")
    domains = json.loads(phantom.get_run_data(key=f"{PLAYBOOK_NAME}:domains") or "[]")
    _run_domain_reputation(container, domains)
    return


@phantom.playbook_block()
def domain_reputation_1_callback(action=None, success=None, container=None, results=None,
                                 handle=None, filtered_artifacts=None, filtered_results=None,
                                 custom_function=None):
    phantom.debug(f"{PLAYBOOK_NAME}: domain_reputation_1_callback() called")
    ips = json.loads(phantom.get_run_data(key=f"{PLAYBOOK_NAME}:ips") or "[]")
    _run_ip_reputation(container, ips)
    return


@phantom.playbook_block()
def ip_reputation_1_callback(action=None, success=None, container=None, results=None,
                             handle=None, filtered_artifacts=None, filtered_results=None,
                             custom_function=None):
    phantom.debug(f"{PLAYBOOK_NAME}: ip_reputation_1_callback() called")
    _finish_summary(container)
    return


@phantom.playbook_block()
def on_finish(container, summary):
    phantom.debug(f"{PLAYBOOK_NAME}: on_finish() called")
    return
