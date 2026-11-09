#!/usr/bin/env python3
"""Genera samples/sample.pcap con tráfico OT variado para probar OTScope.
Uso: python3 samples/make_sample.py"""
import os
import struct
from scapy.all import Ether, IP, TCP, Raw, wrpcap

HERE = os.path.dirname(os.path.abspath(__file__))
PLC = "192.168.10.10"      # PLC Modbus
ENG = "192.168.10.50"      # estación de ingeniería (legítima)
ATK = "192.168.10.99"      # host sospechoso interno
SCAN = "192.168.10.77"     # host que enumera
PUB = "45.134.26.5"        # dirección pública (no debería hablar OT)


def modbus(unit, pdu):
    length = 1 + len(pdu)
    return struct.pack(">HHHB", 0, 0, length, unit) + pdu


def mb_pkt(src, dst, unit, pdu, sport=50000):
    return Ether() / IP(src=src, dst=dst) / TCP(sport=sport, dport=502, flags="PA") / Raw(modbus(unit, pdu))


pkts = []
# Lecturas legítimas (FC 3)
pkts.append(mb_pkt(ENG, PLC, 1, b"\x03\x00\x00\x00\x0a"))
# Escritura a registro único (FC 6) -> ALTA
pkts.append(mb_pkt(ENG, PLC, 1, b"\x06\x00\x01\x00\x7b"))
# Escritura múltiple (FC 16) -> ALTA
pkts.append(mb_pkt(ENG, PLC, 1, b"\x10\x00\x00\x00\x02\x04\x00\x0a\x00\x0b"))
# Diagnóstico / restart comms (FC 8) desde host sospechoso -> CRÍTICA
pkts.append(mb_pkt(ATK, PLC, 1, b"\x08\x00\x01\xff\x00", sport=50001))
# Lectura de identidad del dispositivo (FC 43/MEI) -> MEDIA (recon)
pkts.append(mb_pkt(ATK, PLC, 1, b"\x2b\x0e\x01\x00", sport=50001))
# Barrido de unit IDs (FC 3 a 8 unidades) -> MEDIA (enumeración)
for u in range(1, 9):
    pkts.append(mb_pkt(SCAN, PLC, u, b"\x03\x00\x00\x00\x01", sport=50002))
# Modbus desde una IP pública -> CRÍTICA (exposición)
pkts.append(mb_pkt(PUB, PLC, 1, b"\x03\x00\x00\x00\x05", sport=40000))

# --- DNP3 (puerto 20000) — energía/agua ---
RTU = "192.168.10.11"       # estación remota DNP3
DMASTER = "192.168.10.60"   # maestro DNP3 legítimo
DATK = "192.168.10.98"      # host sospechoso


def dnp3(dnp_dst, app_func, control=0xc4):
    userdata = bytes([0xc0, 0xc0, app_func])          # transport + app ctrl + func
    length = 5 + len(userdata)                        # control + dst(2) + src(2) + datos
    frame = bytes([0x05, 0x64, length, control]) + struct.pack("<HH", dnp_dst, 1)
    frame += b"\x00\x00" + userdata + b"\x00\x00"     # CRCs (relleno, no se validan)
    return frame


def dnp_pkt(src, func, dnp_dst=1024, sport=51000):
    return Ether() / IP(src=src, dst=RTU) / TCP(sport=sport, dport=20000, flags="PA") / Raw(dnp3(dnp_dst, func))


pkts.append(dnp_pkt(DMASTER, 1))              # READ legítimo
pkts.append(dnp_pkt(DATK, 4, sport=51001))    # OPERATE -> CRÍTICA (acciona salida física)
pkts.append(dnp_pkt(DATK, 13, sport=51001))   # COLD_RESTART -> CRÍTICA
pkts.append(dnp_pkt(DATK, 2, sport=51001))    # WRITE -> ALTA
for d in range(1, 9):                         # barrido de direcciones DNP3 -> MEDIA
    pkts.append(dnp_pkt(SCAN, 1, dnp_dst=d, sport=51002))

# --- S7comm (puerto 102) — PLCs Siemens ---
S7PLC = "192.168.10.12"
S7ENG = "192.168.10.61"     # TIA Portal legítimo
S7ATK = "192.168.10.97"     # host sospechoso


def s7_job(func, extra=b""):
    param = bytes([func]) + extra
    s7 = bytes([0x32, 0x01, 0x00, 0x00, 0x00, 0x01]) + struct.pack(">H", len(param)) + struct.pack(">H", 0) + param
    cotp = bytes([0x02, 0xf0, 0x80])
    tpkt = bytes([0x03, 0x00]) + struct.pack(">H", 4 + len(cotp) + len(s7))
    return tpkt + cotp + s7


def s7_pkt(src, func, sport=52000):
    return Ether() / IP(src=src, dst=S7PLC) / TCP(sport=sport, dport=102, flags="PA") / Raw(s7_job(func))


pkts.append(s7_pkt(S7ENG, 0xf0))              # Setup communication -> info
pkts.append(s7_pkt(S7ENG, 0x04))              # Read Var -> BAJA
pkts.append(s7_pkt(S7ATK, 0x05, sport=52001)) # Write Var -> ALTA
pkts.append(s7_pkt(S7ATK, 0x29, sport=52001)) # PLC Stop -> CRÍTICA
pkts.append(s7_pkt(S7ATK, 0x1a, sport=52001)) # Request download -> CRÍTICA

# --- EtherNet/IP (puerto 44818) — Allen-Bradley/Rockwell ---
EIPPLC = "192.168.10.13"
EIPENG = "192.168.10.62"
EIPATK = "192.168.10.96"


def eip(cip):
    items = struct.pack("<HH", 0, 0) + struct.pack("<HH", 0x00B2, len(cip)) + cip
    cpf = struct.pack("<IH", 0, 0) + struct.pack("<H", 2) + items
    encap = struct.pack("<HH", 0x6F, len(cpf)) + struct.pack("<II", 0, 0) + b"\x00" * 8 + struct.pack("<I", 0)
    return encap + cpf


def eip_pkt(src, cip, sport=53000):
    return Ether() / IP(src=src, dst=EIPPLC) / TCP(sport=sport, dport=44818, flags="PA") / Raw(eip(cip))


pkts.append(eip_pkt(EIPENG, b"\x4c\x02\x20\x01\x24\x01"))              # Read Tag -> (sin hallazgo, lectura normal)
pkts.append(eip_pkt(EIPATK, b"\x4d\x02\x20\x01\x24\x01", sport=53001)) # Write Tag -> ALTA
pkts.append(eip_pkt(EIPATK, b"\x05\x02\x20\x01\x24\x01", sport=53001)) # Reset -> CRÍTICA
pkts.append(eip_pkt(EIPATK, b"\x07\x02\x20\x01\x24\x01", sport=53001)) # Stop -> CRÍTICA

# --- IEC 60870-5-104 (puerto 2404) — telecontrol eléctrico ---
RTU104 = "192.168.10.14"       # estación / RTU IEC-104
MASTER104 = "192.168.10.63"    # maestro SCADA legítimo
ATK104 = "192.168.10.94"       # host sospechoso


def iec104(type_id, extra=b"", cot=6, ca=1, ioa=1):
    # ASDU: typeid, VSQ(1 obj), COT(2), dir común(2 LE), IOA(3) + info
    asdu = bytes([type_id, 0x01, cot & 0x3f, 0x00]) + struct.pack("<H", ca) + struct.pack("<I", ioa)[:3] + extra
    length = 4 + len(asdu)          # 4 octetos de control I-format + ASDU
    return bytes([0x68, length, 0x00, 0x00, 0x00, 0x00]) + asdu


def i104_pkt(src, type_id, extra=b"", sport=54000, ca=1):
    return Ether() / IP(src=src, dst=RTU104) / TCP(sport=sport, dport=2404, flags="PA") / Raw(iec104(type_id, extra, ca=ca))


pkts.append(i104_pkt(MASTER104, 100, b"\x14"))                 # interrogación (recon, maestro)
pkts.append(i104_pkt(ATK104, 45, b"\x01", sport=54001))        # Single command -> CRÍTICA
pkts.append(i104_pkt(ATK104, 105, b"\x00", sport=54001))       # Reset process -> CRÍTICA
pkts.append(i104_pkt(ATK104, 48, b"\x00\x00\x01", sport=54001))# Set-point -> ALTA

# Tráfico web normal -> debe ser ignorado
pkts.append(Ether() / IP(src=ENG, dst=PLC) / TCP(sport=50020, dport=80, flags="PA") / Raw(b"GET / HTTP/1.1\r\n"))

out = os.path.join(HERE, "sample.pcap")
wrpcap(out, pkts)
print(f"[ok] {out} — {len(pkts)} paquetes")

# --- Captura "sana" para el baseline: SOLO tráfico legítimo de las estaciones
#     autorizadas (sin atacantes, sin comandos sospechosos). ---
normal = []
normal.append(mb_pkt(ENG, PLC, 1, b"\x03\x00\x00\x00\x0a"))          # lectura legítima
normal.append(mb_pkt(ENG, PLC, 1, b"\x06\x00\x01\x00\x7b"))          # escritura de la estación de ingeniería
normal.append(dnp_pkt(DMASTER, 1))                                    # DNP3: READ del maestro legítimo
normal.append(s7_pkt(S7ENG, 0xf0))                                    # S7: setup
normal.append(s7_pkt(S7ENG, 0x04))                                    # S7: Read Var legítimo
normal.append(eip_pkt(EIPENG, b"\x4c\x02\x20\x01\x24\x01"))          # EtherNet/IP: Read Tag legítimo
normal.append(i104_pkt(MASTER104, 100, b"\x14"))                     # IEC-104: interrogación del maestro

out_b = os.path.join(HERE, "sample_baseline.pcap")
wrpcap(out_b, normal)
print(f"[ok] {out_b} — {len(normal)} paquetes (tráfico sano para --learn)")
