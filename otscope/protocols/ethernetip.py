"""Dissector profundo de EtherNet/IP + CIP (puerto 44818) — PLCs Allen-Bradley /
Rockwell y muchos dispositivos industriales.

Desempaqueta el header de encapsulación EtherNet/IP, el Common Packet Format y el
mensaje CIP para detectar servicios que CONTROLAN o REPROGRAMAN el dispositivo
(Reset, Stop/Start de la CPU, escritura de tags/atributos) y reconocimiento. Entra
también en los Multiple Service Packet, donde suelen esconderse los comandos.

Referencia: ODVA — The CIP Networks Library (Vol. 1 y 2).
"""
from ..core import Finding

NAME = "EtherNet/IP (CIP)"
PORTS = [44818]

ENCAP_SENDRR = 0x6F   # SendRRData (mensaje no conectado)
ENCAP_SENDUNIT = 0x70  # SendUnitData (mensaje conectado)
ENCAP_LISTID = 0x63    # ListIdentity (descubrimiento)
ENCAP_LISTSVC = 0x64   # ListServices (descubrimiento)

# Servicios CIP y su criticidad.
RESET = 0x05        # reinicia el dispositivo
START = 0x06        # arranca la CPU
STOP = 0x07         # detiene la CPU (modo program)
MSP = 0x0A          # Multiple Service Packet (contenedor)
WRITE_SVC = {
    0x02: "Set_Attributes_All", 0x04: "Set_Attribute_List",
    0x10: "Set_Attribute_Single", 0x4D: "Write Tag", 0x53: "Write Tag Fragmented",
    0x4E: "Read-Modify-Write Tag", 0x08: "Create", 0x09: "Delete",
}
RECON_SVC = {0x01: "Get_Attributes_All", 0x03: "Get_Attribute_List"}


def _cip_services(cip, depth=0, acc=None):
    """Devuelve la lista de códigos de servicio de una petición CIP,
    entrando recursivamente en los Multiple Service Packet."""
    if acc is None:
        acc = []
    if len(cip) < 2 or depth > 3:
        return acc
    svc = cip[0]
    if svc & 0x80:   # es una respuesta, no una petición
        return acc
    path_size = cip[1]
    data_start = 2 + path_size * 2
    acc.append(svc)
    if svc == MSP and data_start + 2 <= len(cip):
        body = cip[data_start:]
        n = body[0] | (body[1] << 8)
        offs = []
        for i in range(n):
            o = 2 + i * 2
            if o + 2 > len(body):
                return acc
            offs.append(body[o] | (body[o + 1] << 8))
        for j, o in enumerate(offs):
            end = offs[j + 1] if j + 1 < len(offs) else len(body)
            if 0 <= o <= len(body):
                _cip_services(body[o:end], depth + 1, acc)
    return acc


def _extract_cip(p):
    """Localiza el mensaje CIP dentro de un SendRRData/SendUnitData, o None."""
    if len(p) < 24:
        return None
    cmd = p[0] | (p[1] << 8)
    if cmd not in (ENCAP_SENDRR, ENCAP_SENDUNIT):
        return None
    off = 24 + 6  # header de encapsulación (24) + interface handle (4) + timeout (2)
    if off + 2 > len(p):
        return None
    item_count = p[off] | (p[off + 1] << 8)
    off += 2
    cip = None
    for _ in range(item_count):
        if off + 4 > len(p):
            break
        itype = p[off] | (p[off + 1] << 8)
        ilen = p[off + 2] | (p[off + 3] << 8)
        off += 4
        if itype == 0xB2:              # Unconnected Data Item
            cip = p[off:off + ilen]
        elif itype == 0xB1 and ilen >= 2:  # Connected Data Item (2 bytes de seq)
            cip = p[off + 2:off + ilen]
        off += ilen
    return cip


def inspect(ctx, info):
    p = info["payload"]
    if not info["to_service"] or len(p) < 24:
        return
    src, dst = info["src"], info["dst"]
    cmd = p[0] | (p[1] << 8)

    if cmd in (ENCAP_LISTID, ENCAP_LISTSVC):
        ctx.add_finding(Finding(
            "media", NAME, "Descubrimiento de dispositivos",
            f"{src} envió un '{'ListIdentity' if cmd == ENCAP_LISTID else 'ListServices'}' "
            f"a {dst}. Enumera dispositivos EtherNet/IP en la red: fase de reconocimiento.",
            src=src, dst=dst))
        return

    cip = _extract_cip(p)
    if not cip:
        return
    services = _cip_services(cip)

    for svc in services:
        if svc == RESET:
            ctx.add_finding(Finding(
                "critica", NAME, "Reinicio del dispositivo (CIP Reset)",
                f"{src} envió un servicio 'Reset' a {dst}. Reinicia el dispositivo: "
                f"corta el control del proceso. Impacto operativo directo.",
                src=src, dst=dst))
        elif svc == STOP:
            ctx.add_finding(Finding(
                "critica", NAME, "Parada de la CPU (CIP Stop)",
                f"{src} envió 'Stop' a {dst}. Pasa el PLC a modo program/detenido: "
                f"deja de ejecutar su lógica de control.",
                src=src, dst=dst))
        elif svc == START:
            ctx.add_finding(Finding(
                "alta", NAME, "Arranque de la CPU (CIP Start)",
                f"{src} envió 'Start' a {dst}. Cambia el modo de ejecución del PLC.",
                src=src, dst=dst))
        elif svc in WRITE_SVC:
            ctx.add_finding(Finding(
                "alta", NAME, "Escritura en el dispositivo",
                f"{src} usó '{WRITE_SVC[svc]}' contra {dst}. "
                f"Modifica tags, atributos o la configuración del PLC.",
                src=src, dst=dst))
        elif svc in RECON_SVC:
            ctx.add_finding(Finding(
                "media", NAME, "Reconocimiento del dispositivo",
                f"{src} usó '{RECON_SVC[svc]}' contra {dst}. "
                f"Lee atributos del dispositivo: típico de enumeración/reconocimiento.",
                src=src, dst=dst))
