"""Salida de OTScope: terminal (con color) y JSON."""
import datetime as dt
import json
from .core import SEV_WEIGHT
from .advice import advise

_C = {"critica": "\033[1;35m", "alta": "\033[1;31m", "media": "\033[1;33m",
      "baja": "\033[1;36m", "info": "\033[2;37m",
      "b": "\033[1m", "dim": "\033[2m", "x": "\033[0m"}
_LABEL = {"critica": "CRÍTICA", "alta": "ALTA", "media": "MEDIA", "baja": "BAJA", "info": "INFO"}


def _no_color():
    for k in _C:
        _C[k] = ""


def _summary(ctx):
    counts = {}
    for f in ctx.findings.values():
        counts[f.sev] = counts.get(f.sev, 0) + 1
    return counts


def terminal(ctx, path, color=True):
    if not color:
        _no_color()
    c = _C
    counts = _summary(ctx)
    out = []
    out.append(f"\n{c['b']}OTScope — análisis de {path}{c['x']}")
    out.append(f"{c['dim']}{ctx.packets} paquetes · {ctx.ot_packets} de protocolos OT · "
               f"{len(ctx.hosts)} hosts · {len(ctx.protocols)} protocolos{c['x']}")
    if ctx.protocols:
        prot = ", ".join(f"{k} ({v})" for k, v in sorted(ctx.protocols.items(), key=lambda x: -x[1]))
        out.append(f"{c['dim']}Protocolos: {prot}{c['x']}")
    if ctx.baseline:
        b = ctx.baseline
        out.append(f"{c['b']}Comparado contra baseline{c['x']} {c['dim']}"
                   f"({b['hosts_baseline']} hosts, {b['comportamientos_baseline']} comportamientos conocidos){c['x']}")
        out.append(f"  {c['alta']}{b['anomalias']} anomalías{c['x']}{c['dim']} · "
                   f"{b['conocidos']} comportamientos esperados · "
                   f"{b['dispositivos_nuevos']} dispositivos nuevos{c['x']}")
    out.append("")

    findings = sorted(ctx.findings.values(),
                      key=lambda f: (-SEV_WEIGHT[f.sev], f.proto, f.title))
    if not findings:
        out.append(f"{c['media']}No se detectaron hallazgos.{c['x']}\n")
    else:
        out.append(f"{c['b']}Hallazgos ({len(findings)}){c['x']}")
        for f in findings:
            badge = f"{c[f.sev]}{_LABEL[f.sev]:<8}{c['x']}"
            conv = ""
            if f.src and f.dst:
                conv = f"  {c['dim']}{f.src} → {f.dst}{c['x']}"
            elif f.src:
                conv = f"  {c['dim']}{f.src}{c['x']}"
            rep = f"  {c['dim']}×{f.count}{c['x']}" if f.count > 1 else ""
            tag = ""
            if f.baseline == "anomalo":
                tag = f"{c['alta']}⚠ ANOMALÍA{c['x']} "
            elif f.baseline == "conocido":
                tag = f"{c['dim']}✓ baseline{c['x']} "
            out.append(f"  [{badge}] {tag}{c['b']}{f.proto}{c['x']} — {f.title}{conv}{rep}")
            if f.detail:
                out.append(f"            {c['dim']}{f.detail}{c['x']}")
            adv = advise(f.title)
            if adv:
                out.append(f"            {c['b']}↳ Mitigación:{c['x']} {c['dim']}{adv['fix']}{c['x']}")
                if adv["refs"]:
                    out.append(f"            {c['dim']}  Ref: {' · '.join(adv['refs'])}{c['x']}")
        out.append("")

    # inventario de dispositivos
    if ctx.hosts:
        out.append(f"{c['b']}Dispositivos OT vistos{c['x']}")
        for ip, h in sorted(ctx.hosts.items(), key=lambda x: -x[1]['pkts']):
            protos = ", ".join(sorted(h["protos"])) or "—"
            out.append(f"  {c['dim']}{ip:<16}{c['x']} {protos}  {c['dim']}({h['pkts']} pkts){c['x']}")
        out.append("")

    # resumen final
    parts = []
    for sev in ("critica", "alta", "media", "baja", "info"):
        if counts.get(sev):
            parts.append(f"{c[sev]}{counts[sev]} {_LABEL[sev].lower()}{c['x']}")
    out.append(f"{c['b']}Resumen:{c['x']} " + " · ".join(parts) if parts else "Resumen: sin hallazgos")
    out.append("")
    return "\n".join(out)


def to_payload(ctx, path):
    """Estructura de datos del informe (dict). La usan to_json() y la app web."""
    findings = sorted(ctx.findings.values(),
                      key=lambda f: (-SEV_WEIGHT[f.sev], f.proto, f.title))
    return {
        "archivo": path,
        "generado": dt.datetime.now().isoformat(timespec="seconds"),
        "resumen": {
            "paquetes": ctx.packets, "paquetes_ot": ctx.ot_packets,
            "hosts": len(ctx.hosts), "protocolos": ctx.protocols,
            "por_severidad": _summary(ctx),
        },
        "dispositivos": [
            {"ip": ip, "protocolos": sorted(h["protos"]), "paquetes": h["pkts"]}
            for ip, h in sorted(ctx.hosts.items(), key=lambda x: -x[1]["pkts"])
        ],
        "baseline": ctx.baseline,
        "hallazgos": [_finding_dict(f) for f in findings],
    }


def _finding_dict(f):
    d = f.to_dict()
    adv = advise(f.title)
    if adv:
        d["mitigacion"] = adv["fix"]
        d["referencias"] = adv["refs"]
    return d


def to_json(ctx, path):
    return json.dumps(to_payload(ctx, path), ensure_ascii=False, indent=2)
