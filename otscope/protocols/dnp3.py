"""Dissector profundo de DNP3 (puerto 20000) — muy común en energía eléctrica,
agua y gas.

Parsea la capa de enlace (start 0x0564) y la capa de aplicación para detectar
funciones que CONTROLAN o REPROGRAMAN una estación remota (OPERATE sobre salidas
físicas, reinicios, parada de aplicación, escritura) y patrones de reconocimiento
(enumeración de direcciones DNP3).

Referencia: IEEE 1815-2012 (DNP3), capa de aplicación.
"""
from ..core import Finding

NAME = "DNP3"
PORTS = [20000]

START = b"\x05\x64"

# Códigos de función de la capa de aplicación (peticiones maestro -> outstation).
FUNC = {
    0: "CONFIRM", 1: "READ", 2: "WRITE", 3: "SELECT", 4: "OPERATE",
    5: "DIRECT_OPERATE", 6: "DIRECT_OPERATE_NR", 7: "FREEZE",
    13: "COLD_RESTART", 14: "WARM_RESTART", 15: "INITIALIZE_DATA",
    16: "INITIALIZE_APPLICATION", 17: "START_APPLICATION",
    18: "STOP_APPLICATION", 19: "SAVE_CONFIGURATION",
    20: "ENABLE_UNSOLICITED", 21: "DISABLE_UNSOLICITED",
    22: "ASSIGN_CLASS", 23: "DELAY_MEASUREMENT",
}
# Actúan sobre salidas físicas (interruptores, relés): el mayor impacto.
CONTROL_FC = {4: "OPERATE", 5: "DIRECT_OPERATE", 6: "DIRECT_OPERATE_NR"}
# Reinician o detienen la estación remota.
RESTART_FC = {13: "COLD_RESTART", 14: "WARM_RESTART", 18: "STOP_APPLICATION"}
# Modifican estado/configuración.
WRITE_FC = {2: "WRITE", 15: "INITIALIZE_DATA", 19: "SAVE_CONFIGURATION"}

ENUM_THRESHOLD = 6  # direcciones DNP3 distintas desde un mismo origen => barrido


def _state(ctx):
    return ctx.scratch.setdefault("dnp3", {})  # src -> {"dests": set, "fcs": set}


def inspect(ctx, info):
    p = info["payload"]
    if len(p) < 13 or p[0:2] != START:
        return
    length = p[2]
    if length <= 5:
        return  # frame solo de capa de enlace (sin datos de aplicación)
    # Capa de enlace: dirección destino/origen en little-endian.
    dnp_dst = p[4] | (p[5] << 8)
    # p[10]=transport, p[11]=application control, p[12]=application function
    app_func = p[12]
    if app_func not in FUNC:
        return
    # Respuestas (RESPONSE=129, UNSOLICITED=130) y cualquier cosa del outstation: ignorar.
    if not info["to_service"] or app_func >= 128:
        return

    src, dst = info["src"], info["dst"]
    st = _state(ctx)
    entry = st.setdefault(src, {"dests": set(), "fcs": set()})
    entry["dests"].add(dnp_dst)
    entry["fcs"].add(app_func)

    if app_func in CONTROL_FC:
        ctx.add_finding(Finding(
            "critica", NAME, "Control de salida física (OPERATE)",
            f"{src} envió '{CONTROL_FC[app_func]}' a {dst} (dirección DNP3 {dnp_dst}). "
            f"Esta función acciona salidas físicas: relés, interruptores, válvulas. "
            f"Un OPERATE no autorizado puede abrir o cerrar un interruptor real.",
            src=src, dst=dst))
    elif app_func in RESTART_FC:
        ctx.add_finding(Finding(
            "critica", NAME, "Reinicio o parada de la estación remota",
            f"{src} envió '{RESTART_FC[app_func]}' a {dst} (dir DNP3 {dnp_dst}). "
            f"Reinicia o detiene el outstation: pérdida de monitoreo y control.",
            src=src, dst=dst))
    elif app_func in WRITE_FC:
        ctx.add_finding(Finding(
            "alta", NAME, "Escritura o cambio de configuración",
            f"{src} envió '{WRITE_FC[app_func]}' a {dst} (dir DNP3 {dnp_dst}). "
            f"Modifica datos o la configuración de la estación remota.",
            src=src, dst=dst))
    elif app_func == 3:  # SELECT (el paso previo del select-before-operate)
        ctx.add_finding(Finding(
            "alta", NAME, "SELECT (previo a un OPERATE)",
            f"{src} envió 'SELECT' a {dst} (dir DNP3 {dnp_dst}). "
            f"Arma una salida para operarla: suele venir seguido de un OPERATE.",
            src=src, dst=dst))
    elif app_func == 21:  # DISABLE_UNSOLICITED
        ctx.add_finding(Finding(
            "media", NAME, "Se deshabilitan respuestas no solicitadas",
            f"{src} envió 'DISABLE_UNSOLICITED' a {dst}. "
            f"Silencia los eventos espontáneos del outstation: puede cegar el monitoreo.",
            src=src, dst=dst))


def finalize(ctx):
    st = ctx.scratch.get("dnp3", {})
    for src, entry in st.items():
        if len(entry["dests"]) >= ENUM_THRESHOLD:
            ctx.add_finding(Finding(
                "media", NAME, "Barrido de direcciones DNP3 (reconocimiento)",
                f"{src} se dirigió a {len(entry['dests'])} direcciones DNP3 distintas. "
                f"Patrón típico de enumeración de estaciones remotas.",
                src=src))
