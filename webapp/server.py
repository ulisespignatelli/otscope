#!/usr/bin/env python3
"""Servidor web local de OTScope — dashboard para analizar capturas OT.

Sin dependencias extra (solo la librería estándar + scapy, que ya usa el motor).
Todo corre en tu máquina: la captura nunca sale de la PC.

Uso:
    python webapp/server.py            # abre en http://127.0.0.1:8000
    python webapp/server.py --port 9000 --no-browser

El front sube el .pcap como bytes crudos a /api/analyze; el servidor lo guarda en
un archivo temporal, corre el motor de OTScope y devuelve el informe en JSON.
"""
import argparse
import json
import os
import sys
import tempfile
import threading
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from otscope import analyze, build_registry, report  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
INDEX = os.path.join(HERE, "index.html")
MAX_UPLOAD = 200 * 1024 * 1024  # 200 MB


class Handler(BaseHTTPRequestHandler):
    server_version = "OTScope/2.0"

    def _send(self, code, body, ctype="application/json; charset=utf-8"):
        if isinstance(body, str):
            body = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        # Sin recursos externos: todo local, sin llamadas a internet.
        self.send_header("Content-Security-Policy", "default-src 'self' 'unsafe-inline'")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path in ("/", "/index.html"):
            try:
                with open(INDEX, "rb") as f:
                    self._send(200, f.read(), "text/html; charset=utf-8")
            except FileNotFoundError:
                self._send(500, "index.html no encontrado", "text/plain; charset=utf-8")
        elif self.path == "/health":
            self._send(200, json.dumps({"ok": True}))
        else:
            self._send(404, "No encontrado", "text/plain; charset=utf-8")

    def do_POST(self):
        if self.path != "/api/analyze":
            self._send(404, json.dumps({"error": "ruta desconocida"}))
            return
        try:
            length = int(self.headers.get("Content-Length", 0))
        except ValueError:
            length = 0
        if length <= 0:
            self._send(400, json.dumps({"error": "no se recibió ningún archivo"}))
            return
        if length > MAX_UPLOAD:
            self._send(413, json.dumps({"error": "archivo demasiado grande (máx 200 MB)"}))
            return

        data = self.rfile.read(length)
        fname = self.headers.get("X-Filename", "captura.pcap")
        tmp = tempfile.NamedTemporaryFile(prefix="otscope_", suffix=".pcap", delete=False)
        try:
            tmp.write(data)
            tmp.close()
            ctx = analyze(tmp.name, build_registry())
            payload = report.to_payload(ctx, os.path.basename(fname))
            self._send(200, json.dumps(payload, ensure_ascii=False))
        except Exception as e:  # el motor no debe tumbar el servidor
            self._send(500, json.dumps({"error": f"no se pudo analizar la captura: {e}"}))
        finally:
            try:
                os.unlink(tmp.name)
            except OSError:
                pass

    def log_message(self, fmt, *args):
        # log mínimo y limpio
        sys.stderr.write("  %s - %s\n" % (self.address_string(), fmt % args))


def main(argv=None):
    ap = argparse.ArgumentParser(description="Dashboard web local de OTScope.")
    ap.add_argument("--port", type=int, default=8000)
    ap.add_argument("--host", default="127.0.0.1",
                    help="por defecto 127.0.0.1 (solo tu máquina). No lo expongas a la red.")
    ap.add_argument("--no-browser", action="store_true", help="no abrir el navegador solo")
    args = ap.parse_args(argv)

    httpd = ThreadingHTTPServer((args.host, args.port), Handler)
    url = f"http://{args.host}:{args.port}"
    print(f"OTScope web → {url}")
    print("  Análisis 100% local. Ctrl+C para salir.\n")
    if not args.no_browser:
        threading.Timer(0.6, lambda: webbrowser.open(url)).start()
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nServidor detenido.")
        httpd.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
