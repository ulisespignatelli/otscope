"""Dissector profundo de IEC 60870-5-104 (IEC-104, puerto 2404) — telecontrol en
redes eléctricas (SCADA de distribuidoras y transportistas de energía).

Parsea la APCI (formato I/S/U) y la ASDU para detectar comandos que CONTROLAN el
proceso eléctrico: comandos a interruptores (abrir/cerrar), cambios de set-point,
reset de la estación, y patrones de reconocimiento (interrogación general). Es el
análogo del OPERATE de DNP3 en el mundo IEC.

Referencia: IEC 60870-5-104 / 60870-5-101 (ASDU, Type IDs y causa de transmisión).
"""
from ..core import Finding

NAME = "IEC 60870-5-104"
PORTS = [2404]

START = 0x68

# Type IDs de COMANDO (maestro -> estación). Los más sensibles.
CONTROL_CMD = {
    45: "Single command (C_SC) — abrir/cerrar",
    46: "Double command (C_DC) — abrir/cerrar",
    47: "Regulating step command (C_RC)",
    58: "Single command c/tiempo (C_SC_TA)",
    59: "Double command c/tiempo (C_DC_TA)",
    60: "Regulating step c/tiempo (C_RC_TA)",
}
SETPOINT_CMD = {
    48: "Set-point normalizado (C_SE_NA)", 49: "Set-point escalado (C_SE_NB)",
    50: "Set-point flotante (C_SE_NC)", 51: "Bitstring 32 bits (C_BO)",
    61: "Set-point norm. c/tiempo", 62: "Set-point esc. c/tiempo",
    63: "Set-point float c/tiempo", 64: "Bitstring c/tiempo",
}
RESET_CMD = {105: "Reset process command (C_RP)"}
CLOCK_CMD = {103: "Clock synchronization (C_CS)"}
RECON_CMD = {100: "Interrogation (C_IC)", 101: "Counter interrogation (C_CI)",
             102: "Read command (C_RD)"}

# U-format: funciones de control de la conexión.
U_STOPDT_ACT = 0x13   # detiene la transferencia de datos

ENUM_THRESHOLD = 6     # direcciones comunes (estaciones) distintas => barrido


def _state(ctx):
    return ctx.scratch.setdefault("iec104", {})   # src -> set(common_addr)


def inspect(ctx, info):
    p = info["payload"]
    if not info["to_service"]:
        return
    src, dst = info["src"], info["dst"]
    i = 0
    n = len(p)
    # un segmento TCP puede traer varias APDUs encadenadas
    while i + 2 <= n and p[i] == START:
        length = p[i + 1]
        apdu_end = i + 2 + length
        if length < 4 or apdu_end > n:
            break
        c1 = p[i + 2]
        if c1 & 0x01:  # S-format (01) o U-format (11): sin ASDU
            if (c1 & 0x03) == 0x03 and c1 == U_STOPDT_ACT:
                ctx.add_finding(Finding(
                    "media", NAME, "Se detiene la transferencia de datos (STOPDT)",
                    f"{src} envió STOPDT a {dst}. Corta el flujo de datos del telecontrol: "
                    f"puede cegar el monitoreo del SCADA.", src=src, dst=dst))
            i = apdu_end
            continue
        # I-format: hay ASDU a partir de i+6
        if i + 10 >= n:
            break
        type_id = p[i + 6]
        common_addr = p[i + 10] | (p[i + 11] << 8) if i + 11 < n else 0

        st = _state(ctx)
        st.setdefault(src, set())

        if type_id in CONTROL_CMD:
            ctx.add_finding(Finding(
                "critica", NAME, "Comando de control a un interruptor",
                f"{src} envió '{CONTROL_CMD[type_id]}' a {dst} (estación {common_addr}). "
                f"Acciona un equipo físico de la red eléctrica: abrir o cerrar un "
                f"interruptor/seccionador. Un comando no autorizado tiene impacto real.",
                src=src, dst=dst))
        elif type_id in RESET_CMD:
            ctx.add_finding(Finding(
                "critica", NAME, "Reset de la estación (C_RP)",
                f"{src} envió 'Reset process' a {dst} (estación {common_addr}). "
                f"Reinicia la unidad de telecontrol: pérdida de monitoreo y control.",
                src=src, dst=dst))
        elif type_id in SETPOINT_CMD:
            ctx.add_finding(Finding(
                "alta", NAME, "Cambio de set-point",
                f"{src} envió '{SETPOINT_CMD[type_id]}' a {dst} (estación {common_addr}). "
                f"Modifica una consigna del proceso (tensión, potencia, etc.).",
                src=src, dst=dst))
        elif type_id in CLOCK_CMD:
            ctx.add_finding(Finding(
                "media", NAME, "Sincronización de reloj (C_CS)",
                f"{src} sincronizó el reloj de {dst}. Si no es parte de la operación "
                f"normal, puede usarse para alterar marcas de tiempo de eventos.",
                src=src, dst=dst))
        elif type_id in RECON_CMD:
            st[src].add(common_addr)
            ctx.add_finding(Finding(
                "media", NAME, "Reconocimiento (interrogación)",
                f"{src} envió '{RECON_CMD[type_id]}' a {dst} (estación {common_addr}). "
                f"Consulta el estado de la estación: normal en un maestro, sospechoso "
                f"desde un origen desconocido.", src=src, dst=dst))

        i = apdu_end


def finalize(ctx):
    st = ctx.scratch.get("iec104", {})
    for src, addrs in st.items():
        if len(addrs) >= ENUM_THRESHOLD:
            ctx.add_finding(Finding(
                "media", NAME, "Barrido de estaciones (reconocimiento)",
                f"{src} interrogó {len(addrs)} direcciones comunes (estaciones) distintas. "
                f"Patrón típico de enumeración de la red de telecontrol.", src=src))
