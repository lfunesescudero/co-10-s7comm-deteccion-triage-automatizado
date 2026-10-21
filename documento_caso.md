# CO-10: Detección de reconocimiento S7comm y triage automatizado

## 1. Objetivo y alcance

Detectar tráfico S7comm de reconocimiento dirigido a un controlador industrial simulado y automatizar el triage de la IP de origen: detección, enriquecimiento con inteligencia de amenazas y clasificación con salida estructurada.

Entorno técnico aislado sobre Kali Linux: honeypot Conpot en Docker como controlador Siemens simulado, Suricata 8.0.6 en modo IDS sobre la interfaz `docker0`, n8n Community Edition como motor de automatización y AbuseIPDB como fuente de reputación. El tráfico lo genera el analista con Nmap. Suricata detecta y alerta, no bloquea. Se omitió la IP pública del entorno en la evidencia publicada.

## 2. Arquitectura

```
Nmap -> puerto 102 del host -> docker-proxy -> Conpot (10201) en docker0
Suricata (captura en docker0, sid 9001001) -> eve.json
tail -F + grep + curl -> Webhook n8n (producción)
HTTP Request -> AbuseIPDB -> If (abuseConfidenceScore >= 50)
  true -> Ficha URGENTE | false -> Ficha REVISAR
```

| Componente | Función | Despliegue |
|---|---|---|
| Conpot | Controlador Siemens simulado, registra cada sesión S7comm | Docker, puerto 102 del host mapeado al 10201 |
| Suricata 8.0.6 | IDS sin bloqueo | Captura en `docker0`, regla `co10-s7comm.rules` |
| eve.json | Registro estructurado de alertas | Origen de la automatización |
| n8n Community | Recepción, enriquecimiento, clasificación y salida | Docker, flujo publicado con webhook de producción |
| AbuseIPDB | Reputación de la IP de origen | API v2, ventana de 90 días |

Decisiones de diseño:
- **Interfaz.** Se fijó `docker0` porque el tráfico hacia Conpot cruza ese puente tras el reenvío de puerto. El origen observado (`172.17.0.1`) coincide con el registrado por Conpot, lo que permite contrastar ambas fuentes.
- **Puerto.** La firma apunta al 10201, donde Conpot atiende S7comm. El 102 es el puerto expuesto en el host, no el observado en `docker0`.
- **Detección por bytes.** Suricata no incorpora analizador de aplicación para S7comm (`app_proto: failed`), por lo que la firma evalúa bytes de cabecera sobre TCP.

## 3. Detección

```
alert tcp any any -> $HOME_NET 10201 (msg:"CO10 - S7comm Userdata hacia Conpot"; flow:established,to_server; content:"|03 00|"; depth:2; content:"|32 07|"; offset:7; depth:2; classtype:attempted-recon; sid:9001001; rev:2;)
```

**Hipótesis y decisión.** El reconocimiento sobre un PLC Siemens comienza con mensajes S7comm de tipo userdata, que transportan consultas de información del equipo. Se decidió detectar esa clase de mensaje y no cualquier sesión S7comm, para reducir ruido sobre el tráfico de negociación.

| Elemento | Valor | Significado |
|---|---|---|
| Destino | `$HOME_NET` puerto 10201 | Puerto donde Conpot atiende S7comm |
| `flow` | `established,to_server` | Sesión establecida, sentido cliente a servidor |
| `03 00`, `depth:2` | Cabecera TPKT | Encapsulado de transporte |
| `32 07`, `offset:7` | Cabecera S7 | Protocol ID `0x32`, ROSCTR `0x07` (userdata) |
| `sid` | 9001001 | Identificador propio, fuera del rango de las firmas P09 |

**Evidencia.** La firma cargó sin errores con `suricata -T`. Con tráfico de Nmap sobre el puerto 102 del host, Suricata alertó desde `172.17.0.1` hacia `172.17.0.2:10201`. Conpot registró la misma sesión con tres paquetes S7 (uno `pdu_type:1`, dos `pdu_type:7`). Archivos: `co10-s7comm.rules`, `conpot_log.txt`, `eve_alertas.json`.

**Criterio de tuning.** La firma verifica el tipo userdata, no la función SZL específica. Se ajustó el mensaje (`rev:2`) para reflejar exactamente lo que evalúa. Una sesión genera tres alertas con el mismo `flow_id`; la deduplicación se difiere a la capa de automatización.

## 4. Automatización

1. **Envío.** `tail -F` sobre `eve.json` con `grep` de `event_type:alert` y `curl` POST al webhook de producción de n8n, una llamada por alerta.
2. **Enriquecimiento.** Nodo HTTP Request a AbuseIPDB con `ipAddress` tomado de `body.src_ip` y `maxAgeInDays=90`. La clave se almacena como credencial de n8n, fuera del flujo exportable.
3. **Clasificación.** Nodo If sobre `abuseConfidenceScore` con umbral 50: por encima, ficha URGENTE; por debajo, ficha REVISAR.
4. **Salida.** Objeto JSON con veredicto, IP de origen, regla, severidad de Suricata, puntaje, indicador de IP pública y marca de tiempo.

## 5. Resultados

- **Caso contra Conpot.** Origen `172.17.0.1` (IP privada de Docker): puntaje 0, `isPublic: false`, veredicto REVISAR. Archivo: `ficha_caso_real.json`.
- **Prueba de la rama URGENTE.** Se reemplazó el origen por una IP pública de la documentación de AbuseIPDB (`118.25.6.39`, puntaje 7) y se bajó el umbral temporalmente a 5: el flujo clasificó URGENTE. Con el umbral en 50 la misma alerta clasificó REVISAR. Archivos: `evento_publico.json`, `abuseipdb_respuesta.json`.
- **Automatización de extremo a extremo.** Una sola sesión generó tres ejecuciones del flujo, todas exitosas, sin intervención manual.

## 6. Limitaciones y mejoras

- El origen del tráfico es una IP privada, por lo que la reputación no es significativa; la rama URGENTE se validó con evento modificado y umbral reducido.
- Sin deduplicación: una sesión produce tres ejecuciones (mismo `flow_id`). Mejora: agrupar por `flow_id` antes de procesar.
- La firma detecta userdata, no la función SZL. Mejora: ubicar los bytes de función y afinar la coincidencia.
- El script `s7-info` de Nmap no interpreta la respuesta de Conpot; el tráfico que la firma evalúa se genera igual.
