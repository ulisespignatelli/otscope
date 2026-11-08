"""Baseline: aprende el comportamiento NORMAL de una red OT y detecta desviaciones.

Idea: en una red SCADA real los comandos de control son normales (el maestro opera
las RTUs todo el día). Marcar cada uno como crítico es ruido. Con un baseline,
OTScope distingue lo esperado de lo ANÓMALO — que es lo que de verdad importa en
seguridad OT: algo que no debería estar ahí.

Flujo:
  1. Modo aprendizaje: se analiza una captura de tráfico sano y se guarda un perfil
     (hosts conocidos, conversaciones y comportamientos/hallazgos vistos).
  2. Modo comparación: se analiza una captura nueva y cada hallazgo se reclasifica:
       - 'conocido'  -> ya estaba en el baseline  => se baja a informativo.
       - 'anomalo'   -> no estaba                  => se resalta (lo que hay que mirar).
     Además se marcan los dispositivos OT que no aparecían en el baseline.

IMPORTANTE: el baseline debe generarse de una red que se SABE sana. Si se aprende de
una captura que ya tiene un ataque, se aprendería el ataque como "normal".
"""
import datetime as dt
import json

from .core import Finding

VERSION = 1


def build(ctx):
    """Construye el perfil de baseline a partir de un Context ya analizado."""
    def _k(t):  # orden estable aunque haya None (hallazgos globales sin src/dst)
        return tuple("" if x is None else str(x) for x in t)

    hosts = sorted(ctx.hosts.keys())
    pairs = sorted({(s, d, proto) for (s, d, _dp, proto) in ctx.conversations}, key=_k)
    # cada f.key() es (proto, title, src, dst); guardamos el conjunto
    behaviors = sorted({f.key() for f in ctx.findings.values()}, key=_k)
    return {
        "version": VERSION,
        "generado": dt.datetime.now().isoformat(timespec="seconds"),
        "hosts": hosts,
        "conversaciones": [list(p) for p in pairs],
        "comportamientos": [list(b) for b in behaviors],
    }


def save(profile, path):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(profile, f, ensure_ascii=False, indent=2)


def load(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def apply(ctx, profile):
    """Compara el análisis actual contra el baseline y anota los hallazgos.

    Muta ctx.findings: baja los conocidos a informativo, marca los anómalos y suma
    hallazgos por dispositivos OT nuevos. Deja metadatos en ctx.baseline.
    """
    known_hosts = set(profile.get("hosts", []))
    # comportamientos conocidos, como tuplas (proto, title, src, dst)
    known_beh = {tuple(b) for b in profile.get("comportamientos", [])}

    anomalias = 0
    conocidos = 0
    for f in list(ctx.findings.values()):
        if f.key() in known_beh:
            f.baseline = "conocido"
            f.sev = "info"
            if "esperado" not in f.detail:
                f.detail = (f.detail + " · Comportamiento presente en el baseline "
                            "(esperado).").strip()
            conocidos += 1
        else:
            f.baseline = "anomalo"
            f.detail = "⚠ ANOMALÍA — no visto en el baseline. " + f.detail
            anomalias += 1

    # dispositivos OT que no estaban en el baseline
    nuevos = [ip for ip in ctx.hosts if ip not in known_hosts]
    for ip in sorted(nuevos):
        protos = ", ".join(sorted(ctx.hosts[ip]["protos"])) or "OT"
        f = Finding(
            "alta", "Baseline", "Dispositivo OT nuevo (no está en el baseline)",
            f"{ip} ({protos}) no aparecía en el baseline. Un equipo nuevo hablando "
            f"protocolos OT puede ser un activo no autorizado o un atacante.",
            src=ip)
        f.baseline = "anomalo"
        ctx.add_finding(f)

    ctx.baseline = {
        "generado": profile.get("generado"),
        "hosts_baseline": len(known_hosts),
        "comportamientos_baseline": len(known_beh),
        "anomalias": anomalias + len(nuevos),
        "conocidos": conocidos,
        "dispositivos_nuevos": len(nuevos),
    }
    return ctx
