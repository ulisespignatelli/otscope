# OTScope 🔌🛰️

![tests](https://github.com/ulisespignatelli/otscope/actions/workflows/tests.yml/badge.svg)
![python](https://img.shields.io/badge/python-3.9%2B-blue.svg)
![license](https://img.shields.io/badge/license-MIT-green.svg)
![status](https://img.shields.io/badge/an%C3%A1lisis-pasivo-success.svg)

Analizador de seguridad **pasivo** para capturas de red **OT/ICS** (industriales). Le das un archivo `.pcap`/`.pcapng` y detecta los protocolos industriales en uso (Modbus, DNP3, S7, EtherNet/IP, BACnet, IEC-104…) y los **patrones de riesgo**: comandos de escritura/control a dispositivos, reconocimiento, tráfico en texto plano y exposición a direcciones públicas.

**Es 100% pasivo: solo lee la captura, no envía nada a la red.** Pensado para defensores, analistas de SOC/OT y forense industrial.

Cada hallazgo incluye una **recomendación de mitigación** y su **referencia al estándar** (IEC 62443, NIST SP 800-82, IEEE 1815) — pensado para usarse directo en un informe de auditoría.

Por [Ulises Pignatelli](https://github.com/ulisespignatelli) — UP Security.

---

## ¿Por qué?

El tráfico OT es un mundo aparte: protocolos como Modbus o DNP3 **no tienen autenticación ni cifrado** y controlan procesos físicos (energía, agua, industria). Las herramientas de red tradicionales no entienden estos protocolos ni el riesgo que implican. OTScope mira una captura y responde: *¿quién le está dando órdenes a los PLCs? ¿hay reconocimiento? ¿algo de esto llega desde internet?*

## Qué detecta

**Modbus/TCP**
- Comandos de **escritura** (FC 5/6/15/16/22/23) — alguien modifica el estado de un PLC → **ALTA**
- Comandos de **diagnóstico/control** (FC 8: reinicio de comunicaciones, modo escucha) → **CRÍTICA**
- **Reconocimiento**: lectura de identidad (FC 43/MEI) y barrido de unit IDs → **MEDIA**

**DNP3** (energía/agua)
- **OPERATE / DIRECT_OPERATE** — acciona salidas físicas (relés, interruptores) → **CRÍTICA**
- **COLD/WARM_RESTART, STOP_APPLICATION** — reinicia o detiene la estación remota → **CRÍTICA**
- **WRITE / SELECT / SAVE_CONFIG** → **ALTA**
- `DISABLE_UNSOLICITED` y **barrido de direcciones DNP3** → **MEDIA**

**S7comm** (PLCs Siemens)
- **PLC Stop** y **PI service** — detienen o controlan la CPU → **CRÍTICA**
- **Descarga de programa** (request/download/ended) — reprogramación del PLC → **CRÍTICA**
- **Write Var** (escribe memoria/salidas) y **Upload** (extrae la lógica) → **ALTA**
- **Userdata / Read SZL** (identificación y estado de la CPU, reconocimiento) → **MEDIA**

**EtherNet/IP + CIP** (Allen-Bradley/Rockwell)
- **Reset** y **Stop** de la CPU — reinician o detienen el PLC → **CRÍTICA**
- **Start** y **escrituras** (Write Tag, Set_Attribute, Create/Delete) → **ALTA**
- **Get_Attributes_All/List** (reconocimiento) y **ListIdentity/ListServices** (descubrimiento) → **MEDIA**
- Entra en los **Multiple Service Packet**, donde suelen esconderse los comandos.

**Reglas globales (cualquier protocolo OT)**
- **Texto plano** (todos lo son por diseño) → **MEDIA**
- **Tráfico OT con direcciones públicas** (exposición a internet) → **CRÍTICA**
- **Inventario** de dispositivos y protocolos vistos en la red.

Disección profunda: **Modbus, DNP3, S7comm, EtherNet/IP**. Detección por puerto: **BACnet, IEC 60870-5-104, OPC UA, MQTT**.

## Uso

```bash
git clone https://github.com/ulisespignatelli/otscope
cd otscope
pip install -r requirements.txt

python3 otscope.py captura.pcap
python3 otscope.py captura.pcapng --json informe.json
```

¿No tenés una captura a mano? Generá una de ejemplo:

```bash
python3 samples/make_sample.py
python3 otscope.py samples/sample.pcap
```

### Dashboard web (local)

Para una vista visual, arrastrá el `.pcap` y mirá los hallazgos en el navegador:

```bash
python3 webapp/server.py        # abre http://127.0.0.1:8000
```

Corre **100% en tu máquina** (sin dependencias extra, sin recursos externos): la
captura nunca sale de la PC — clave cuando analizás tráfico OT sensible. Permite
filtrar por severidad y **exportar el informe** en HTML o JSON.

### Probar con capturas reales

¿Querés ver OTScope sobre tráfico de verdad? Estos datasets públicos tienen
capturas de redes ICS/SCADA, varias con escenarios de ataque documentados:

| Dataset | Protocolos | Notas |
|---|---|---|
| [ITI/ICS-Security-Tools](https://github.com/ITI/ICS-Security-Tools/tree/master/pcaps) | Modbus, DNP3, EtherNet/IP, Profinet, BACnet, IEC 61850 | `pcaps/openics/` trae ataques: `EIP-RebootorRestart`, `DNP3-SelectOperate`, etc. Ideal para empezar. |
| [tjcruz-dei/ICS_PCAPS](https://github.com/tjcruz-dei/ICS_PCAPS) | Modbus | Dataset de la U. de Coimbra, con tráfico normal y de ataque. |
| [automayt/ICS-pcap](https://github.com/automayt/ICS-pcap) | Muchos (Modbus, DNP3, S7, EtherNet/IP…) | Gran colección recopilada de la comunidad. |
| [4SICS / Netresec](https://www.netresec.com/?page=PCAP4SICS) | Varios OT | Capturas de la ICS Lab del congreso 4SICS. |

```bash
git clone https://github.com/ITI/ICS-Security-Tools.git
python3 otscope.py ICS-Security-Tools/pcaps/openics/EIP-RebootorRestart.pcap
```

> ⚠️ Son capturas de **laboratorio**, para práctica. Para analizar una red real
> necesitás **autorización por escrito** del dueño de esa red.

### Códigos de salida
| Código | Significado |
|---|---|
| `0` | Sin hallazgos altos ni críticos |
| `1` | Al menos un hallazgo **alto o crítico** |

Útil para integrarlo en un pipeline de monitoreo.

## Arquitectura (modular)

```
otscope/
├── otscope.py              # CLI
├── otscope/
│   ├── core.py             # lectura de pcap, inventario, reglas globales
│   ├── report.py           # salida terminal / JSON
│   ├── advice.py           # mitigaciones + mapeo a estándares (IEC 62443 / NIST)
│   └── protocols/
│       ├── __init__.py     # registro puerto -> dissector
│       ├── modbus.py       # disección profunda de Modbus/TCP
│       ├── dnp3.py         # disección profunda de DNP3
│       ├── s7comm.py       # disección profunda de S7comm (Siemens)
│       ├── ethernetip.py   # disección profunda de EtherNet/IP (CIP)
│       └── generic.py      # detección por puerto del resto
├── webapp/
│   ├── server.py           # servidor web local (stdlib, sin deps extra)
│   └── index.html          # dashboard (offline, exporta HTML/JSON)
├── samples/make_sample.py  # genera un pcap de prueba
└── test_otscope.py         # tests
```

## 🤝 Contribuir

Este proyecto está pensado para crecer **con la comunidad**. La forma más útil de aportar es sumar **disección profunda de un protocolo** (IEC 60870-5-104, BACnet, OPC UA…): hoy se detectan por puerto, pero falta analizar sus comandos como ya se hace con Modbus, DNP3, S7comm y EtherNet/IP.

1. Copiá la estructura de `otscope/protocols/modbus.py` (un módulo con `NAME`, `PORTS`, `inspect(ctx, info)` y opcional `finalize(ctx)`).
2. Registralo en `otscope/protocols/__init__.py`.
3. Agregá un caso de prueba en `test_otscope.py`.
4. Mandá tu Pull Request.

Ver [CONTRIBUTING.md](CONTRIBUTING.md) para el detalle.

## ⚠️ Aviso

Herramienta de análisis pasivo y educativa. Analizá solo capturas de redes que te pertenezcan o que estés autorizado a revisar. No reemplaza una auditoría OT formal.

## Licencia

MIT — ver [LICENSE](LICENSE).
