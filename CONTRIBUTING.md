# Contribuir a OTScope

¡Gracias por querer aportar! OTScope busca ser una herramienta comunitaria de análisis OT/ICS. Toda ayuda suma: código, protocolos nuevos, reglas, docs o capturas de ejemplo.

## Formas de contribuir

- **Sumar un protocolo con disección profunda** (la más valiosa): hoy DNP3, S7, EtherNet/IP, etc. se detectan por puerto. Implementar el análisis de sus comandos es un gran aporte.
- **Agregar reglas de seguridad** a un protocolo existente.
- **Mejorar reportes** (por ejemplo, salida HTML).
- **Aportar capturas de ejemplo** (anonimizadas) para tests.
- **Documentación y traducciones.**

## Cómo agregar un protocolo

1. Creá `otscope/protocols/<protocolo>.py` con esta forma:

   ```python
   from ..core import Finding

   NAME = "DNP3"
   PORTS = [20000]

   def inspect(ctx, info):
       # info: src, dst, sport, dport, svc_port, transport, payload (bytes), to_service
       payload = info["payload"]
       # … analizá el payload y, si corresponde:
       ctx.add_finding(Finding("alta", NAME, "Título corto",
                               "Detalle claro de qué pasó y por qué importa.",
                               src=info["src"], dst=info["dst"]))

   def finalize(ctx):   # opcional: reglas que necesitan ver todo el tráfico
       pass
   ```

2. Registralo en `otscope/protocols/__init__.py` dentro de `build_registry()`.

3. Agregá un test en `test_otscope.py` (podés construir el `payload` a mano, sin scapy).

## Severidades

`critica` · `alta` · `media` · `baja` · `info`. Usá el criterio de **impacto operativo**: un comando que puede detener o alterar un proceso físico es crítico; una lectura informativa es info.

## Antes de tu PR

- Corré los tests: `python3 test_otscope.py` (deben pasar todos).
- Un hallazgo nuevo = un test nuevo.
- Mantené el estilo: código y mensajes claros, en español.

## Código de conducta

Respeto y buena onda. Esto es para ayudar a defender infraestructura, no para atacarla: no se aceptan aportes orientados a dañar sistemas de terceros.
