"""Motor de OTScope: lee una captura, identifica protocolos OT/ICS por puerto,
los despacha a los dissectors y acumula inventario + hallazgos de seguridad.

Todo es análisis pasivo de una captura (.pcap/.pcapng) — no envía nada a la red.
"""
import ipaddress

# Severidades y su peso para ordenar / puntuar.
SEV_WEIGHT = {"critica": 4, "alta": 3, "media": 2, "baja": 1, "info": 0}


class Finding:
    __slots__ = ("sev", "proto", "title", "detail", "src", "dst", "count", "baseline")

    def __init__(self, sev, proto, title, detail="", src=None, dst=None, count=1):
        self.sev = sev
        self.proto = proto
        self.title = title
        self.detail = detail
        self.src = src
        self.dst = dst
        self.count = count
        # estado respecto del baseline: None (sin baseline), "conocido" o "anomalo"
        self.baseline = None

    def key(self):
        # para agrupar hallazgos repetidos (misma regla + mismo par origen/destino)
        return (self.proto, self.title, self.src, self.dst)

    def to_dict(self):
        d = {"severidad": self.sev, "protocolo": self.proto, "titulo": self.title,
             "detalle": self.detail, "origen": self.src, "destino": self.dst,
             "ocurrencias": self.count}
        if self.baseline:
            d["baseline"] = self.baseline
        return d


class Context:
    """Estado compartido que los dissectors van llenando."""
    def __init__(self):
        self.findings = {}          # key -> Finding (agrupados)
        self.hosts = {}             # ip -> {"protos": set(), "pkts": int}
        self.conversations = {}     # (src,dst,dport,proto) -> count
        self.protocols = {}         # proto -> count de paquetes
        self.packets = 0
        self.ot_packets = 0
        self.scratch = {}           # espacio de estado para los dissectors
        self.baseline = None        # metadatos del baseline comparado (si hubo)

    def add_finding(self, f):
        existing = self.findings.get(f.key())
        if existing:
            existing.count += f.count
        else:
            self.findings[f.key()] = f

    def seen_host(self, ip, proto=None):
        h = self.hosts.setdefault(ip, {"protos": set(), "pkts": 0})
        h["pkts"] += 1
        if proto:
            h["protos"].add(proto)

    def seen_conversation(self, src, dst, dport, proto):
        k = (src, dst, dport, proto)
        self.conversations[k] = self.conversations.get(k, 0) + 1
        self.protocols[proto] = self.protocols.get(proto, 0) + 1
        self.ot_packets += 1


def is_public(ip):
    """True si la IP es globalmente ruteable (una dirección pública de internet)."""
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return False  # ante la duda, no la marcamos como pública


def analyze(path, registry):
    """Lee la captura y la procesa paquete por paquete.

    registry: dict puerto -> módulo dissector (con .NAME y .inspect(ctx, pkt_info)).
    Devuelve un Context con el inventario y los hallazgos.
    """
    # Import diferido para que importar el core no exija scapy (ej. en tests unitarios).
    from scapy.all import PcapReader, IP, IPv6, TCP, UDP, Raw

    ctx = Context()
    with PcapReader(path) as pcap:
        for pkt in pcap:
            ctx.packets += 1
            ip_layer = pkt.getlayer(IP) or pkt.getlayer(IPv6)
            if ip_layer is None:
                continue
            src = ip_layer.src
            dst = ip_layer.dst
            l4 = pkt.getlayer(TCP) or pkt.getlayer(UDP)
            if l4 is None:
                continue
            transport = "tcp" if pkt.haslayer(TCP) else "udp"
            sport, dport = int(l4.sport), int(l4.dport)
            payload = bytes(pkt[Raw].load) if pkt.haslayer(Raw) else b""

            # El puerto "de servicio" OT suele ser el menor / el conocido.
            diss = registry.get(dport) or registry.get(sport)
            if diss is None:
                continue

            proto = diss.NAME
            ctx.seen_host(src, proto)
            ctx.seen_host(dst, proto)
            # orientamos la conversación hacia el puerto de servicio conocido
            if dport in registry:
                c_src, c_dst, svc_port = src, dst, dport
            else:
                c_src, c_dst, svc_port = dst, src, sport
            ctx.seen_conversation(c_src, c_dst, svc_port, proto)

            info = {"src": c_src, "dst": c_dst, "sport": sport, "dport": dport,
                    "svc_port": svc_port, "transport": transport, "payload": payload,
                    "to_service": dport in registry}
            try:
                diss.inspect(ctx, info)
            except Exception:
                # un dissector no debe tumbar el análisis completo
                pass

    # hooks de cierre: reglas agregadas por dissector (ej. enumeración)
    for diss in set(registry.values()):
        if hasattr(diss, "finalize"):
            try:
                diss.finalize(ctx)
            except Exception:
                pass

    _global_rules(ctx)
    return ctx


def _global_rules(ctx):
    """Reglas que aplican a cualquier protocolo OT, una vez procesado todo."""
    # 1) Protocolos OT en texto plano (ninguno de estos cifra por diseño).
    for proto, n in ctx.protocols.items():
        ctx.add_finding(Finding(
            "media", proto, "Protocolo OT sin cifrado",
            f"{proto} viaja en texto plano por diseño ({n} paquetes). "
            f"Un atacante en la red puede leer y potencialmente alterar el tráfico.",
            count=1))

    # 2) Tráfico OT hacia/desde direcciones públicas (posible exposición a internet).
    for (src, dst, port, proto), n in ctx.conversations.items():
        if is_public(src) or is_public(dst):
            pub = src if is_public(src) else dst
            ctx.add_finding(Finding(
                "critica", proto, "Tráfico OT con una dirección pública",
                f"Conversación {proto} con {pub} (puerto {port}). "
                f"Los sistemas OT no deberían ser accesibles desde internet.",
                src=src, dst=dst))
