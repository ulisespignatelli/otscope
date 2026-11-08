#!/usr/bin/env python3
"""Tests de OTScope. Los de lógica no necesitan scapy; el de integración lee el
pcap de ejemplo. Ejecutar: python3 test_otscope.py"""
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from otscope.core import Context, is_public, _global_rules
from otscope.protocols import modbus, dnp3, s7comm, ethernetip


def mbap(unit, pdu):
    return struct.pack(">HHHB", 0, 0, 1 + len(pdu), unit) + pdu


def info(src, dst, payload, to_service=True, svc_port=502):
    return {"src": src, "dst": dst, "sport": 5000, "dport": 502, "svc_port": svc_port,
            "transport": "tcp", "payload": payload, "to_service": to_service}


def has(ctx, sev=None, title_contains=None):
    for f in ctx.findings.values():
        if (sev is None or f.sev == sev) and (title_contains is None or title_contains in f.title):
            return True
    return False


CASES = []


def check(name, cond):
    CASES.append((name, bool(cond)))


# --- Modbus: escritura -> ALTA ---
ctx = Context()
modbus.inspect(ctx, info("10.0.0.5", "10.0.0.10", mbap(1, b"\x06\x00\x01\x00\x7b")))
check("FC6 (write) => ALTA", has(ctx, "alta", "escritura"))

# --- Modbus: diagnóstico -> CRÍTICA ---
ctx = Context()
modbus.inspect(ctx, info("10.0.0.5", "10.0.0.10", mbap(1, b"\x08\x00\x01\xff\x00")))
check("FC8 (diagnostics) => CRÍTICA", has(ctx, "critica", "diagn"))

# --- Modbus: lectura NO genera hallazgo de escritura ---
ctx = Context()
modbus.inspect(ctx, info("10.0.0.5", "10.0.0.10", mbap(1, b"\x03\x00\x00\x00\x0a")))
check("FC3 (read) no marca escritura", not has(ctx, "alta", "escritura"))

# --- Modbus: respuesta (to_service=False) se ignora ---
ctx = Context()
modbus.inspect(ctx, info("10.0.0.10", "10.0.0.5", mbap(1, b"\x06\x00\x01\x00\x7b"), to_service=False))
check("respuesta del PLC se ignora", not has(ctx, "alta"))

# --- Modbus: barrido de unit IDs -> MEDIA ---
ctx = Context()
for u in range(1, 9):
    modbus.inspect(ctx, info("10.0.0.7", "10.0.0.10", mbap(u, b"\x03\x00\x00\x00\x01")))
modbus.finalize(ctx)
check("barrido de 8 unit IDs => enumeración", has(ctx, "media", "Barrido"))

# --- Payload corto / no-Modbus no rompe ni genera basura ---
ctx = Context()
modbus.inspect(ctx, info("10.0.0.5", "10.0.0.10", b"\x00\x01"))        # muy corto
modbus.inspect(ctx, info("10.0.0.5", "10.0.0.10", b"\x00\x00\x00\x05" + b"\x00" * 6))  # protocol_id!=0
check("payload inválido no genera hallazgos", len(ctx.findings) == 0)

# --- is_public ---
check("45.134.26.5 es pública", is_public("45.134.26.5"))
check("192.168.1.1 no es pública", not is_public("192.168.1.1"))
check("203.0.113.9 (doc) no es pública", not is_public("203.0.113.9"))

# --- regla global: exposición pública -> CRÍTICA ---
ctx = Context()
ctx.seen_conversation("45.134.26.5", "10.0.0.10", 502, "Modbus")
_global_rules(ctx)
check("conversación con IP pública => CRÍTICA", has(ctx, "critica", "pública"))
check("protocolo OT en texto plano => hallazgo", has(ctx, title_contains="sin cifrado"))


# =================== DNP3 ===================
def dnp3_frame(app_func, dnp_dst=1024):
    userdata = bytes([0xc0, 0xc0, app_func])
    length = 5 + len(userdata)
    return (bytes([0x05, 0x64, length, 0xc4]) + struct.pack("<HH", dnp_dst, 1) +
            b"\x00\x00" + userdata + b"\x00\x00")


def dinfo(src, dst, payload, to_service=True):
    return {"src": src, "dst": dst, "sport": 5000, "dport": 20000, "svc_port": 20000,
            "transport": "tcp", "payload": payload, "to_service": to_service}


# OPERATE (control de salida física) -> CRÍTICA
ctx = Context()
dnp3.inspect(ctx, dinfo("10.0.0.5", "10.0.0.11", dnp3_frame(4)))
check("DNP3 OPERATE => CRÍTICA", has(ctx, "critica", "OPERATE"))

# COLD_RESTART -> CRÍTICA
ctx = Context()
dnp3.inspect(ctx, dinfo("10.0.0.5", "10.0.0.11", dnp3_frame(13)))
check("DNP3 COLD_RESTART => CRÍTICA", has(ctx, "critica", "Reinicio"))

# READ no marca control
ctx = Context()
dnp3.inspect(ctx, dinfo("10.0.0.5", "10.0.0.11", dnp3_frame(1)))
check("DNP3 READ no marca control", not has(ctx, "critica"))

# respuesta (func >= 128) se ignora
ctx = Context()
dnp3.inspect(ctx, dinfo("10.0.0.11", "10.0.0.5", dnp3_frame(129), to_service=False))
check("DNP3 respuesta se ignora", len(ctx.findings) == 0)

# barrido de direcciones DNP3 -> MEDIA
ctx = Context()
for d in range(1, 9):
    dnp3.inspect(ctx, dinfo("10.0.0.7", "10.0.0.11", dnp3_frame(1, dnp_dst=d)))
dnp3.finalize(ctx)
check("DNP3 barrido de direcciones => enumeración", has(ctx, "media", "Barrido"))

# frame no-DNP3 no rompe
ctx = Context()
dnp3.inspect(ctx, dinfo("10.0.0.5", "10.0.0.11", b"\x00\x01\x02"))
check("DNP3 payload inválido no genera hallazgos", len(ctx.findings) == 0)


# =================== S7comm ===================
def s7_frame(func):
    param = bytes([func])
    s7 = bytes([0x32, 0x01, 0x00, 0x00, 0x00, 0x01]) + struct.pack(">H", len(param)) + struct.pack(">H", 0) + param
    cotp = bytes([0x02, 0xf0, 0x80])
    return bytes([0x03, 0x00]) + struct.pack(">H", 4 + len(cotp) + len(s7)) + cotp + s7


def sinfo(src, dst, payload, to_service=True):
    return {"src": src, "dst": dst, "sport": 5000, "dport": 102, "svc_port": 102,
            "transport": "tcp", "payload": payload, "to_service": to_service}


# PLC Stop -> CRÍTICA
ctx = Context()
s7comm.inspect(ctx, sinfo("10.0.0.5", "10.0.0.12", s7_frame(0x29)))
check("S7 PLC Stop => CRÍTICA", has(ctx, "critica", "Parada"))

# Download -> CRÍTICA
ctx = Context()
s7comm.inspect(ctx, sinfo("10.0.0.5", "10.0.0.12", s7_frame(0x1a)))
check("S7 download => CRÍTICA", has(ctx, "critica", "Descarga"))

# Write Var -> ALTA
ctx = Context()
s7comm.inspect(ctx, sinfo("10.0.0.5", "10.0.0.12", s7_frame(0x05)))
check("S7 Write Var => ALTA", has(ctx, "alta", "Escritura"))

# Read Var -> BAJA (no crítica/alta)
ctx = Context()
s7comm.inspect(ctx, sinfo("10.0.0.5", "10.0.0.12", s7_frame(0x04)))
check("S7 Read Var => BAJA", has(ctx, "baja", "Lectura") and not has(ctx, "critica"))

# payload no-S7 no rompe
ctx = Context()
s7comm.inspect(ctx, sinfo("10.0.0.5", "10.0.0.12", b"\x03\x00\x00\x05\x02"))
check("S7 payload inválido no genera hallazgos", len(ctx.findings) == 0)


# =================== EtherNet/IP ===================
def eip_frame(cip):
    items = struct.pack("<HH", 0x0000, 0x0000) + struct.pack("<HH", 0x00B2, len(cip)) + cip
    cpf = struct.pack("<IH", 0, 0) + struct.pack("<H", 2) + items
    encap = struct.pack("<HH", 0x6F, len(cpf)) + struct.pack("<II", 0, 0) + b"\x00" * 8 + struct.pack("<I", 0)
    return encap + cpf


def einfo(src, dst, payload, to_service=True):
    return {"src": src, "dst": dst, "sport": 5000, "dport": 44818, "svc_port": 44818,
            "transport": "tcp", "payload": payload, "to_service": to_service}


# CIP Reset -> CRÍTICA
ctx = Context()
ethernetip.inspect(ctx, einfo("10.0.0.5", "10.0.0.20", eip_frame(b"\x05\x02\x20\x01\x24\x01")))
check("EIP Reset => CRÍTICA", has(ctx, "critica", "Reinicio"))

# CIP Stop -> CRÍTICA
ctx = Context()
ethernetip.inspect(ctx, einfo("10.0.0.5", "10.0.0.20", eip_frame(b"\x07\x02\x20\x01\x24\x01")))
check("EIP Stop => CRÍTICA", has(ctx, "critica", "Parada"))

# Write Tag -> ALTA
ctx = Context()
ethernetip.inspect(ctx, einfo("10.0.0.5", "10.0.0.20", eip_frame(b"\x4d\x02\x20\x01\x24\x01")))
check("EIP Write Tag => ALTA", has(ctx, "alta", "Escritura"))

# Read Tag (0x4C) no marca escritura ni crítica
ctx = Context()
ethernetip.inspect(ctx, einfo("10.0.0.5", "10.0.0.20", eip_frame(b"\x4c\x02\x20\x01\x24\x01")))
check("EIP Read Tag no marca control", not has(ctx, "critica") and not has(ctx, "alta"))

# Multiple Service Packet con un Reset adentro -> CRÍTICA (recursión)
inner = b"\x05\x02\x20\x01\x24\x01"
# body = nº de servicios (1) + array de offsets (1×2 bytes) + request embebido.
# El offset apunta al inicio del request, relativo al inicio del body: 2+2 = 4.
body = struct.pack("<H", 1) + struct.pack("<H", 4) + inner
msp = b"\x0a\x02\x20\x02\x24\x01" + body
ctx = Context()
ethernetip.inspect(ctx, einfo("10.0.0.5", "10.0.0.20", eip_frame(msp)))
check("EIP Reset dentro de Multiple Service Packet => CRÍTICA", has(ctx, "critica", "Reinicio"))

# respuesta (to_service=False) se ignora
ctx = Context()
ethernetip.inspect(ctx, einfo("10.0.0.20", "10.0.0.5", eip_frame(b"\x05\x02\x20\x01\x24\x01"), to_service=False))
check("EIP respuesta se ignora", len(ctx.findings) == 0)


# =================== Baseline ===================
from otscope import baseline as bl
from otscope.core import Finding as _F

# baseline "sano": una escritura legítima de ENG->PLC
ctxb = Context()
ctxb.seen_host("10.0.0.5", "Modbus"); ctxb.seen_host("10.0.0.10", "Modbus")
ctxb.seen_conversation("10.0.0.5", "10.0.0.10", 502, "Modbus")
ctxb.add_finding(_F("alta", "Modbus", "Comando de escritura a un dispositivo", "x",
                    src="10.0.0.5", dst="10.0.0.10"))
prof = bl.build(ctxb)
check("baseline.build registra hosts", "10.0.0.5" in prof["hosts"])
check("baseline.build registra comportamientos",
      ["Modbus", "Comando de escritura a un dispositivo", "10.0.0.5", "10.0.0.10"] in prof["comportamientos"])

# captura nueva: misma escritura (conocida) + OPERATE anómalo desde host nuevo
ctxn = Context()
ctxn.seen_host("10.0.0.5", "Modbus"); ctxn.seen_host("10.0.0.10", "Modbus")
ctxn.seen_host("10.0.0.99", "DNP3")
ctxn.add_finding(_F("alta", "Modbus", "Comando de escritura a un dispositivo", "x",
                    src="10.0.0.5", dst="10.0.0.10"))
ctxn.add_finding(_F("critica", "DNP3", "Control de salida física (OPERATE)", "x",
                    src="10.0.0.99", dst="10.0.0.11"))
bl.apply(ctxn, prof)
_w = ctxn.findings[("Modbus", "Comando de escritura a un dispositivo", "10.0.0.5", "10.0.0.10")]
check("baseline: comportamiento conocido baja a info", _w.baseline == "conocido" and _w.sev == "info")
_op = ctxn.findings[("DNP3", "Control de salida física (OPERATE)", "10.0.0.99", "10.0.0.11")]
check("baseline: comportamiento nuevo marcado anómalo", _op.baseline == "anomalo" and _op.sev == "critica")
check("baseline: dispositivo nuevo detectado", has(ctxn, title_contains="Dispositivo OT nuevo"))

# save/load roundtrip
import tempfile as _tf
_f = _tf.NamedTemporaryFile(suffix=".json", delete=False); _f.close()
bl.save(prof, _f.name); _prof2 = bl.load(_f.name); os.unlink(_f.name)
check("baseline save/load roundtrip", _prof2["comportamientos"] == prof["comportamientos"])


# =================== Advice / mitigaciones ===================
from otscope.advice import advise, TITLE_CAT, ADVICE

check("advise() da mitigación para un título conocido",
      advise("Control de salida física (OPERATE)") and
      "fix" in advise("Control de salida física (OPERATE)"))
check("advise() devuelve None para título desconocido", advise("xxx inexistente") is None)
check("toda categoría mapeada existe en ADVICE",
      all(cat in ADVICE for cat in TITLE_CAT.values()))
# la exposición pública debe citar IEC 62443
_exp = advise("Tráfico OT con una dirección pública")
check("exposición pública referencia IEC 62443",
      _exp and any("62443" in r for r in _exp["refs"]))


def integration():
    """Corre el análisis completo sobre el pcap de ejemplo (necesita scapy)."""
    sample = os.path.join(os.path.dirname(__file__), "samples", "sample.pcap")
    if not os.path.isfile(sample):
        return None
    try:
        from otscope import analyze, build_registry
    except Exception:
        return None
    ctx = analyze(sample, build_registry())
    ok = (has(ctx, "critica", "diagn") and has(ctx, "critica", "pública") and
          has(ctx, "alta", "escritura") and
          has(ctx, "critica", "OPERATE") and      # DNP3 profundo
          has(ctx, "critica", "Parada") and       # S7 PLC Stop profundo
          ctx.ot_packets > 10)
    return ok


def main():
    ok = sum(1 for _, c in CASES if c)
    for name, c in CASES:
        print(f"[{'ok ' if c else 'FAIL'}] {name}")
    itg = integration()
    if itg is not None:
        print(f"[{'ok ' if itg else 'FAIL'}] integración sobre sample.pcap")
        CASES.append(("integración", itg))
    fails = sum(1 for _, c in CASES if not c)
    print(f"\n{sum(1 for _,c in CASES if c)} ok, {fails} fallos")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
