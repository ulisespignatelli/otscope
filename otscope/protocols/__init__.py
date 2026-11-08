"""Registro de protocolos: mapea puerto -> dissector.

Para sumar un protocolo nuevo con disección profunda:
  1. Creá un módulo como modbus.py con NAME, PORTS, inspect(ctx, info) y
     (opcional) finalize(ctx).
  2. Importalo acá y registrá sus puertos en build_registry().
"""
from . import modbus, dnp3, s7comm, ethernetip, generic

# Módulos con disección profunda. Para sumar uno nuevo, agregalo a esta lista.
DEEP = [modbus, dnp3, s7comm, ethernetip]


def build_registry():
    reg = {}
    # protocolos genéricos (detección por puerto) primero…
    reg.update(generic.build())
    # …y los que tienen disección profunda pisan el puerto con su módulo.
    for mod in DEEP:
        for port in mod.PORTS:
            reg[port] = mod
    return reg
