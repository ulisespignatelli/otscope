"""Dissector de Modbus/TCP (puerto 502) — el protocolo OT más común.

Analiza el header MBAP y el código de función para detectar comandos que
MODIFICAN o CONTROLAN un dispositivo (escrituras, diagnósticos) y patrones de
reconocimiento (enumeración de unit IDs, lectura de identidad del equipo).

Referencia: Modbus Application Protocol Specification v1.1b3.
"""
from ..core import Finding

NAME = "Modbus"
PORTS = [502]

# Códigos de función de escritura: cambian el estado del dispositivo.
WRITE_FC = {5: "Write Single Coil", 6: "Write Single Register",
            15: "Write Multiple Coils", 16: "Write Multiple Registers",
            22: "Mask Write Register", 23: "Read/Write Multiple Registers"}
READ_FC = {1: "Read Coils", 2: "Read Discrete Inputs",
           3: "Read Holding Registers", 4: "Read Input Registers"}
# Diagnóstico / control: pueden reiniciar comunicaciones o forzar modo escucha.
DIAG_FC = {8: "Diagnostics", 17: "Report Server ID"}
RECON_FC = {43: "Read Device Identification (MEI)", 7: "Read Exception Status",
            11: "Get Comm Event Counter", 12: "Get Comm Event Log"}

ENUM_THRESHOLD = 6  # unit IDs distintos desde un mismo origen => posible barrido


def _state(ctx):
    return ctx.scratch.setdefault("modbus", {})  # src -> {"units": set, "fcs": set}


def inspect(ctx, info):
    p = info["payload"]
    if len(p) < 8:
        return
    # MBAP: transaction(2) protocol(2) length(2) unit(1) | PDU: function(1) ...
    protocol_id = (p[2] << 8) | p[3]
    if protocol_id != 0:
        return  # no es Modbus/TCP
    unit_id = p[6]
    fc = p[7]
    is_exception = bool(fc & 0x80)
    base_fc = fc & 0x7F

    # Solo nos interesan los COMANDOS hacia el dispositivo (cliente -> PLC).
    if not info["to_service"] or is_exception:
        return

    src, dst = info["src"], info["dst"]
    st = _state(ctx)
    entry = st.setdefault(src, {"units": set(), "fcs": set()})
    entry["units"].add(unit_id)
    entry["fcs"].add(base_fc)

    if base_fc in WRITE_FC:
        ctx.add_finding(Finding(
            "alta", NAME, "Comando de escritura a un dispositivo",
            f"{src} envió '{WRITE_FC[base_fc]}' (FC {base_fc}) al dispositivo {dst} "
            f"(unit {unit_id}). Alguien está modificando el estado de un PLC/equipo.",
            src=src, dst=dst))
    elif base_fc == 8:
        ctx.add_finding(Finding(
            "critica", NAME, "Comando de diagnóstico/control",
            f"{src} envió 'Diagnostics' (FC 8) a {dst} (unit {unit_id}). "
            f"Puede reiniciar comunicaciones o forzar modo escucha: alto impacto operativo.",
            src=src, dst=dst))
    elif base_fc in RECON_FC:
        ctx.add_finding(Finding(
            "media", NAME, "Reconocimiento del dispositivo",
            f"{src} consultó '{RECON_FC[base_fc]}' (FC {base_fc}) a {dst}. "
            f"Típico de una fase de reconocimiento/enumeración.",
            src=src, dst=dst))
    elif base_fc == 17:
        ctx.add_finding(Finding(
            "media", NAME, "Reconocimiento del dispositivo",
            f"{src} pidió 'Report Server ID' (FC 17) a {dst}.", src=src, dst=dst))


def finalize(ctx):
    st = ctx.scratch.get("modbus", {})
    for src, entry in st.items():
        if len(entry["units"]) >= ENUM_THRESHOLD:
            ctx.add_finding(Finding(
                "media", NAME, "Barrido de unit IDs (reconocimiento)",
                f"{src} se dirigió a {len(entry['units'])} unit IDs distintos. "
                f"Patrón típico de un escaneo/enumeración de dispositivos Modbus.",
                src=src))
