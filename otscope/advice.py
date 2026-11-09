"""Base de conocimiento: mitigación y referencia a estándares para cada hallazgo.

Cada hallazgo (por su título) se mapea a una categoría, y cada categoría tiene una
recomendación accionable y las referencias a normas (IEC 62443, NIST SP 800-82,
IEEE 1815…). Esto convierte un hallazgo técnico en algo accionable para una
auditoría: qué pasó, qué implica, qué hacer y qué norma lo respalda.

Ampliar es trivial: agregá una categoría a ADVICE y mapeá el título en TITLE_CAT.
"""

# categoría -> {fix: recomendación, refs: [normas]}
ADVICE = {
    "write": {
        "fix": "Restringí qué estaciones pueden escribir en el dispositivo (lista blanca "
               "origen↔PLC), segmentá la red OT y registrá/alertá las escrituras. "
               "Confirmá que el origen sea una estación de ingeniería autorizada.",
        "refs": ["IEC 62443-3-3 SR 2.1 (Authorization enforcement)",
                 "NIST SP 800-82r3 — control de acceso y mínimo privilegio"],
    },
    "physical_control": {
        "fix": "Esta orden acciona equipamiento físico (relés, interruptores). Verificá "
               "que provino de una operación autorizada del SCADA. Aplicá control de "
               "acceso y, si el equipo lo soporta, DNP3 Secure Authentication.",
        "refs": ["IEC 62443-3-3 SR 2.1 / SR 1.1", "IEEE 1815-2012 (DNP3 Secure Authentication)",
                 "NIST SP 800-82r3"],
    },
    "device_control": {
        "fix": "Comando de control de alto impacto (puede detener o reiniciar el proceso). "
               "Debe salir solo de estaciones autorizadas y en ventanas de mantenimiento. "
               "Alertá en tiempo real y deshabilitá el control remoto si no se usa.",
        "refs": ["IEC 62443-3-3 SR 2.1 (Authorization enforcement)",
                 "NIST SP 800-82r3 — mínimo privilegio y respuesta a incidentes"],
    },
    "program_transfer": {
        "fix": "La (re)programación del PLC debe estar estrictamente controlada: solo "
               "ingeniería, con llave física en modo RUN cuando exista. Un download no "
               "planificado puede ser un ataque de manipulación de lógica (tipo Stuxnet).",
        "refs": ["IEC 62443-4-2 CR 3.4 (Software integrity)", "NIST SP 800-82r3"],
    },
    "recon": {
        "fix": "Patrón de reconocimiento: alguien está mapeando los equipos. Verificá si el "
               "origen es una herramienta autorizada; si no, puede ser la fase previa a un "
               "ataque. Investigá el host de origen y alertá estos barridos.",
        "refs": ["IEC 62443-3-3 SR 6.2 (Continuous monitoring)",
                 "NIST SP 800-82r3 — detección y monitoreo"],
    },
    "blind_monitoring": {
        "fix": "Deshabilitar los reportes espontáneos puede cegar el monitoreo del SCADA. "
               "Confirmá que fue un cambio planificado; si no, investigá — se usa para "
               "ocultar manipulaciones.",
        "refs": ["IEC 62443-3-3 SR 6.2 (Continuous monitoring)", "NIST SP 800-82r3"],
    },
    "plaintext": {
        "fix": "Estos protocolos no cifran por diseño. Mitigá con segmentación estricta "
               "(zona/VLAN OT) y, donde sea posible, túneles cifrados o versiones seguras "
               "(OPC UA con seguridad, DNP3-SA). Nadie fuera de la zona OT debería ver este tráfico.",
        "refs": ["IEC 62443-3-3 SR 4.1 (Information confidentiality)",
                 "NIST SP 800-82r3 — segmentación de red"],
    },
    "internet_exposure": {
        "fix": "CRÍTICO: ningún equipo OT debería ser accesible desde internet. Quitá la "
               "exposición ya (firewall, cerrar port-forwarding, activo detrás de una DMZ/zona "
               "OT) y revisá en Shodan si ya está indexado.",
        "refs": ["IEC 62443-3-3 SR 5.1/5.2 (Network segmentation / zone boundary)",
                 "NIST SP 800-82r3 — protección de perímetro", "CISA — ICS no expuestos a internet"],
    },
    "read_low": {
        "fix": "Operación de lectura común. No es un problema en sí; verificá que el origen "
               "sea una estación autorizada.",
        "refs": ["IEC 62443-3-3 SR 2.1"],
    },
    "session": {
        "fix": "Inicio de sesión. Normal entre estaciones de ingeniería y el equipo; "
               "verificá que el origen sea esperado.",
        "refs": [],
    },
    "baseline_new_device": {
        "fix": "Verificá en el inventario de activos si este equipo está autorizado. "
               "Si no lo reconocés, aislalo y analizá qué está haciendo en la red OT.",
        "refs": ["IEC 62443-3-3 SR 1.1 / SR 2.1", "NIST SP 800-82r3 — gestión de activos"],
    },
    "baseline_new_conv": {
        "fix": "Una comunicación no vista antes puede ser un cambio legítimo (equipo nuevo) "
               "o actividad no autorizada. Confirmá con el responsable de la red OT.",
        "refs": ["IEC 62443-3-3 SR 6.2 (Continuous monitoring)", "NIST SP 800-82r3"],
    },
}

# título del hallazgo -> categoría
TITLE_CAT = {
    # Modbus
    "Comando de escritura a un dispositivo": "write",
    "Comando de diagnóstico/control": "device_control",
    "Reconocimiento del dispositivo": "recon",
    "Barrido de unit IDs (reconocimiento)": "recon",
    # DNP3
    "Control de salida física (OPERATE)": "physical_control",
    "SELECT (previo a un OPERATE)": "physical_control",
    "Reinicio o parada de la estación remota": "device_control",
    "Escritura o cambio de configuración": "write",
    "Se deshabilitan respuestas no solicitadas": "blind_monitoring",
    "Barrido de direcciones DNP3 (reconocimiento)": "recon",
    # S7comm
    "Parada de la CPU (PLC Stop)": "device_control",
    "Control de la CPU (PI service)": "device_control",
    "Descarga de programa al PLC": "program_transfer",
    "Escritura de variables (Write Var)": "write",
    "Extracción del programa del PLC (Upload)": "program_transfer",
    "Lectura de variables (Read Var)": "read_low",
    "Lectura de estado/identificación del PLC": "recon",
    "Nueva sesión S7 (COTP Connect)": "session",
    # EtherNet/IP
    "Reinicio del dispositivo (CIP Reset)": "device_control",
    "Parada de la CPU (CIP Stop)": "device_control",
    "Arranque de la CPU (CIP Start)": "device_control",
    "Escritura en el dispositivo": "write",
    "Descubrimiento de dispositivos": "recon",
    # IEC 60870-5-104
    "Comando de control a un interruptor": "physical_control",
    "Reset de la estación (C_RP)": "device_control",
    "Cambio de set-point": "write",
    "Sincronización de reloj (C_CS)": "device_control",
    "Reconocimiento (interrogación)": "recon",
    "Barrido de estaciones (reconocimiento)": "recon",
    "Se detiene la transferencia de datos (STOPDT)": "blind_monitoring",
    # Reglas globales
    "Protocolo OT sin cifrado": "plaintext",
    "Tráfico OT con una dirección pública": "internet_exposure",
    # Baseline
    "Dispositivo OT nuevo (no está en el baseline)": "baseline_new_device",
}


def advise(title):
    """Devuelve {'fix': str, 'refs': [str]} para el título dado, o None si no hay."""
    cat = TITLE_CAT.get(title)
    return ADVICE.get(cat) if cat else None
