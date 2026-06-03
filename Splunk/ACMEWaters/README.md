# ACME WATERS · Splunk SOAR Playbooks

Implementación de referencia en Python de los cinco playbooks descritos en el Sprint 3:

- `PB_ACME_01_Extraer_IOC_Correo.py`
- `PB_ACME_02_Reputacion_Hash_VirusTotal.py`
- `PB_ACME_03_Reputacion_URL_Dominio.py`
- `PB_ACME_04_Clasificacion_Severidad.py`
- `PB_ACME_05_Escalado_SOC.py`

## Requisitos esperados

- Splunk Phantom / Splunk SOAR con soporte de Playbooks Python.
- App VirusTotal v3 instalada.
- Asset configurado con el nombre `virustotal_acme_waters`.
- Artefactos con campos CEF como `fileHashSha256`, `requestURL`, `url`, `domain`,
  `destinationDnsDomain`, `destinationAddress` o `sourceAddress`.
