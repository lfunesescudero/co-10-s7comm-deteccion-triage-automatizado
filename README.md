# CO-10: Detección de reconocimiento S7comm y triage automatizado

Detección de tráfico S7comm de reconocimiento contra un controlador Siemens simulado (Conpot), con Suricata como IDS y un flujo de n8n que enriquece la IP de origen con AbuseIPDB y la clasifica como URGENTE o REVISAR.

## Qué demuestra

- Regla propia de Suricata para S7comm userdata, escrita por bytes de cabecera porque Suricata no tiene analizador de aplicación para este protocolo.
- Contraste de evidencia entre dos fuentes: alerta de Suricata y registro de sesión de Conpot sobre el mismo evento.
- Triage automatizado de extremo a extremo: alerta en `eve.json`, envío por webhook, enriquecimiento de reputación, clasificación por umbral y ficha JSON de salida.

## Stack

Conpot, Docker, Suricata 8.0.6, n8n Community Edition, AbuseIPDB API v2, Nmap, Bash, Kali Linux.

## Contenido

- `documento_caso.md`: caso completo (arquitectura, detección, automatización, resultados, limitaciones).
- `co10-s7comm.rules`: firma de detección (sid 9001001, rev 2).
- `conpot_log.txt`, `nmap_s7info.txt`, `nmap_s7info_2.txt`, `ip_conpot.txt`: línea base del controlador simulado.
- `eve_alertas.json`, `evento_prueba.json`, `evento_publico.json`: alertas de Suricata y eventos usados en el flujo.
- `abuseipdb_respuesta.json`, `ficha_caso_real.json`: respuesta de reputación y ficha de salida.

## Nota

La IP pública del entorno se omitió en la evidencia publicada.
