"""Dissector profundo de S7comm (puerto 102) — PLCs Siemens S7-300/400/1200/1500.

Desempaqueta TPKT + COTP + S7 PDU para detectar funciones que CONTROLAN o
REPROGRAMAN el PLC (parar la CPU, escribir variables, descargar/subir el
programa) y lecturas de estado típicas de reconocimiento.

Referencia: S7comm (ISO-TSAP sobre TPKT, RFC 1006), protocolo propietario de
Siemens documentado por ingeniería inversa (proyecto Wireshark s7comm).
"""
from ..core import Finding

NAME = "S7comm (Siemens)"
PORTS = [102]

S7_MAGIC = 0x32
# ROSCTR (tipo de mensaje)
JOB = 1          # petición del cliente
USERDATA = 7     # funciones extendidas (lectura de SZL, seguridad, etc.)

# Códigos de función de un Job S7 (primer byte del parámetro).
FUNC = {
    0x00: "CPU services", 0x04: "Read Var", 0x05: "Write Var",
    0x1a: "Request download", 0x1b: "Download block", 0x1c: "Download ended",
    0x1d: "Start upload", 0x1e: "Upload", 0x1f: "End upload",
    0x28: "PI service (control)", 0x29: "PLC Stop", 0xf0: "Setup communication",
}
DOWNLOAD_FC = {0x1a: "Request download", 0x1b: "Download block", 0x1c: "Download ended"}
UPLOAD_FC = {0x1d: "Start upload", 0x1e: "Upload", 0x1f: "End upload"}


def _s7_offset(p):
    """Devuelve el offset del PDU S7 (0x32) saltando TPKT(4)+COTP, o -1."""
    if len(p) < 7 or p[0] != 0x03:          # TPKT version
        return -1
    cotp_len = p[4]
    off = 5 + cotp_len                      # TPKT(4) + (COTP len byte + su contenido)
    if off < len(p) and p[off] == S7_MAGIC:
        return off
    return -1


def inspect(ctx, info):
    p = info["payload"]
    if not info["to_service"]:
        return
    off = _s7_offset(p)
    # Conexión COTP (Connection Request, PDU type 0xe0): inicio de sesión S7.
    if off == -1:
        if len(p) >= 6 and p[0] == 0x03 and p[5] == 0xe0:
            ctx.add_finding(Finding(
                "info", NAME, "Nueva sesión S7 (COTP Connect)",
                f"{info['src']} abrió una sesión S7 hacia {info['dst']} (puerto 102).",
                src=info["src"], dst=info["dst"]))
        return

    if off + 10 >= len(p):
        return
    rosctr = p[off + 1]
    src, dst = info["src"], info["dst"]

    if rosctr == USERDATA:
        # Userdata: lecturas de SZL (identificación/estado), funciones de seguridad…
        ctx.add_finding(Finding(
            "media", NAME, "Lectura de estado/identificación del PLC",
            f"{src} usó funciones extendidas (Userdata) contra {dst}. "
            f"Típico de reconocimiento: lee la SZL (modelo, firmware, estado de la CPU).",
            src=src, dst=dst))
        return

    if rosctr != JOB:
        return  # respuestas (Ack/Ack_Data) no nos interesan

    func = p[off + 10]  # primer byte del parámetro (header de Job = 10 bytes)

    if func == 0x29:
        ctx.add_finding(Finding(
            "critica", NAME, "Parada de la CPU (PLC Stop)",
            f"{src} envió 'PLC Stop' a {dst}. Detiene la ejecución del PLC: "
            f"el proceso que controla se queda sin lógica. Impacto operativo directo.",
            src=src, dst=dst))
    elif func == 0x28:
        ctx.add_finding(Finding(
            "critica", NAME, "Control de la CPU (PI service)",
            f"{src} envió un 'PI service' a {dst}. Permite arrancar/parar/reiniciar "
            f"la CPU o borrar memoria. Comando de control de alto impacto.",
            src=src, dst=dst))
    elif func in DOWNLOAD_FC:
        ctx.add_finding(Finding(
            "critica", NAME, "Descarga de programa al PLC",
            f"{src} inició '{DOWNLOAD_FC[func]}' hacia {dst}. "
            f"Se está escribiendo lógica/bloques en el PLC: posible reprogramación.",
            src=src, dst=dst))
    elif func == 0x05:
        ctx.add_finding(Finding(
            "alta", NAME, "Escritura de variables (Write Var)",
            f"{src} envió 'Write Var' a {dst}. Modifica memoria o salidas del PLC.",
            src=src, dst=dst))
    elif func in UPLOAD_FC:
        ctx.add_finding(Finding(
            "alta", NAME, "Extracción del programa del PLC (Upload)",
            f"{src} inició '{UPLOAD_FC[func]}' desde {dst}. "
            f"Lee la lógica del PLC: robo de propiedad intelectual o reconocimiento.",
            src=src, dst=dst))
    elif func == 0x04:
        ctx.add_finding(Finding(
            "baja", NAME, "Lectura de variables (Read Var)",
            f"{src} leyó variables de {dst} (Read Var). Operación común; "
            f"revisá que el origen sea una estación autorizada.",
            src=src, dst=dst))
