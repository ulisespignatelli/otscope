#!/usr/bin/env python3
"""
OTScope — analizador de seguridad de capturas de red OT/ICS.

Lee un archivo .pcap/.pcapng y detecta, de forma PASIVA, protocolos industriales
(Modbus, DNP3, S7, EtherNet/IP, BACnet, IEC-104…) y patrones de riesgo: comandos
de escritura/control a dispositivos, reconocimiento, tráfico en texto plano y
exposición a direcciones públicas. No envía nada a la red: solo lee la captura.

Uso:
    python3 otscope.py captura.pcap
    python3 otscope.py captura.pcapng --json informe.json
    python3 otscope.py captura.pcap --no-color

Códigos de salida:
    0  sin hallazgos de severidad alta o crítica
    1  hay al menos un hallazgo alto o crítico

Autor: Ulises Pignatelli — UP Security. Licencia: MIT.
"""
import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from otscope import analyze, build_registry, report
from otscope.core import SEV_WEIGHT


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Analizador pasivo de seguridad para capturas de red OT/ICS.")
    ap.add_argument("pcap", help="archivo de captura .pcap o .pcapng")
    ap.add_argument("--json", metavar="ARCHIVO", help="escribe el informe en JSON")
    ap.add_argument("--learn", metavar="BASELINE.json",
                    help="aprende el baseline de esta captura (red SANA) y lo guarda")
    ap.add_argument("--baseline", metavar="BASELINE.json",
                    help="compara contra un baseline: resalta solo lo anómalo")
    ap.add_argument("--no-color", action="store_true", help="salida sin color")
    ap.add_argument("--quiet", action="store_true", help="no imprime el informe en terminal")
    args = ap.parse_args(argv)

    if not os.path.isfile(args.pcap):
        sys.stderr.write(f"No se encontró el archivo: {args.pcap}\n")
        return 2

    ctx = analyze(args.pcap, build_registry())

    # Modo aprendizaje: generar el baseline y salir.
    if args.learn:
        from otscope import baseline as bl
        prof = bl.build(ctx)
        bl.save(prof, args.learn)
        print(f"[+] Baseline aprendido de {args.pcap}: "
              f"{len(prof['hosts'])} hosts, {len(prof['comportamientos'])} comportamientos.")
        print(f"[+] Guardado en {args.learn}")
        return 0

    # Modo comparación: anotar hallazgos contra el baseline.
    if args.baseline:
        if not os.path.isfile(args.baseline):
            sys.stderr.write(f"No se encontró el baseline: {args.baseline}\n")
            return 2
        from otscope import baseline as bl
        bl.apply(ctx, bl.load(args.baseline))

    color = not args.no_color and sys.stdout.isatty()
    if not args.quiet:
        print(report.terminal(ctx, args.pcap, color=color))
    if args.json:
        with open(args.json, "w", encoding="utf-8") as f:
            f.write(report.to_json(ctx, args.pcap))
        print(f"[+] Informe JSON escrito en {args.json}")

    worst = max((SEV_WEIGHT[f.sev] for f in ctx.findings.values()), default=0)
    return 1 if worst >= SEV_WEIGHT["alta"] else 0


if __name__ == "__main__":
    sys.exit(main())
