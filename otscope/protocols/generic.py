"""Detectores por puerto para protocolos OT/ICS cuya disección profunda todavía
no está implementada. Marcan presencia (para el inventario y las reglas globales
de texto-plano y exposición a internet).

Sumar disección profunda de cualquiera de estos es una gran contribución:
copiá la estructura de modbus.py y registralo en __init__.py.
"""
from ..core import Finding


class SimpleProto:
    def __init__(self, name, note=""):
        self.NAME = name
        self.note = note

    def inspect(self, ctx, info):
        # La presencia ya la registra el core; dejamos un hallazgo informativo
        # (el motor agrupa duplicados, así que aparece una sola vez por par).
        ctx.add_finding(Finding(
            "info", self.NAME, f"{self.NAME} en uso",
            f"Se detectó tráfico {self.NAME} entre {info['src']} y {info['dst']} "
            f"(puerto {info['svc_port']}). {self.note}".strip(),
            src=info["src"], dst=info["dst"]))


# Protocolo -> (nombre, puerto(s), nota)
CATALOG = [
    # Modbus (502), DNP3 (20000), S7comm (102) y EtherNet/IP (44818) tienen
    # disección profunda propia (ver módulos dedicados).
    ("BACnet", [47808], "Automatización de edificios (HVAC, accesos)."),
    ("IEC 60870-5-104", [2404], "Telecontrol en redes eléctricas."),
    ("OPC UA", [4840], "Interoperabilidad industrial."),
    ("MQTT", [1883], "IoT/IIoT; revisá si tiene autenticación."),
]


def build():
    """Devuelve dict puerto -> instancia detector para todos los del catálogo."""
    reg = {}
    for name, ports, note in CATALOG:
        det = SimpleProto(name, note)
        for port in ports:
            reg[port] = det
    return reg
