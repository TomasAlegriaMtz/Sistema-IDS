"""
main.py - Orquestador del IDS
=============================
Carga la configuracion, arma los modulos y arranca la captura.

Uso:
    sudo ./venv/bin/python3 -m src.main                          # captura EN VIVO
    sudo ./venv/bin/python3 -m src.main --pcap tools/demo.pcap   # modo DEMO (.pcap)
"""
from __future__ import annotations

import argparse

from src.config_loader import load_settings, load_whitelist, detectar_subred
from src.capture import Capturador, direcciones_propias, detectar_gateway
from src.notifier import Notificador
from src.reporter import Reporter
from src.whitelist import ModuloListasBlancas
from src.site_monitor import ModuloMonitoreoSitios
from src.threat_intel import ModuloThreatIntel
from src.forensics import ModuloForense


def main(pcap: str | None = None, auto: bool = False):
    """Arranca el IDS. 'pcap' -> modo demo; 'auto' -> interfaz y subred autodetectadas."""
    print("=" * 64)
    print("  IDS - Sistema de Deteccion de Intrusos")
    print("=" * 64)

    settings = load_settings()
    whitelist = load_whitelist()

    if pcap:
        settings.setdefault("network", {})["pcap_file"] = pcap

    net = settings.setdefault("network", {})
    if auto:
        net["interface"] = "auto"
    if not pcap and (auto or net.get("monitored_subnet") in (None, "", "auto")):
        detectada = detectar_subred()
        if detectada:
            net["monitored_subnet"] = detectada
            print(f"  Subred autodetectada   : {detectada}")
    modo = f"PCAP ({net['pcap_file']})" if net.get("pcap_file") \
        else f"EN VIVO ({net.get('interface')})"
    print(f"  Modo de captura        : {modo}")
    print(f"  Subred vigilada        : {net.get('monitored_subnet')}")
    print(f"  Admin (recibe alertas) : {settings.get('admin', {}).get('email')}")
    print(f"  Equipos autorizados    : {len(whitelist['equipos'])}")
    print("-" * 64)

    notificador = Notificador(settings)
    reporter = Reporter(settings)

    forense = ModuloForense(settings, notificador, reporter=reporter)

    # El propio equipo (sensor) no se marca como intruso (sin estar en la lista blanca).
    ips_propias, macs_propias = set(), set()
    if net.get("ignorar_equipo_local", True):
        ips_propias, macs_propias = direcciones_propias()
        print(f"  Equipo propio (ignorado): {len(ips_propias)} IPs / {len(macs_propias)} MACs")

    # IPs que NUNCA se bloquean en modo IPS: propias + autorizadas + gateway.
    protegidas = set(ips_propias) | set(whitelist.get("ips", set()))
    gw = detectar_gateway()
    if gw:
        protegidas.add(gw)

    modulo1 = ModuloListasBlancas(settings, whitelist, notificador, reporter=reporter,
                                  ips_propias=ips_propias, macs_propias=macs_propias,
                                  protegidas=protegidas)
    modulo2 = ModuloMonitoreoSitios(settings, reporter)
    modulo3 = ModuloThreatIntel(settings, notificador, forense=forense, reporter=reporter,
                                protegidas=protegidas)

    cap = Capturador(settings)
    cap.registrar(modulo1.handler)
    cap.registrar(modulo2.handler)
    cap.registrar(modulo3.handler)

    print("  Modulos activos:")
    print("    [1] Listas Blancas (Capa 2 y 3)")
    print("    [2] Monitoreo de Sitios (DNS/HTTP)")
    print("    [3] IPs Peligrosas (Threat Intelligence)")
    print("    [4] Automatizacion Forense (Whois / AbuseIPDB)")
    print("  Presiona Ctrl+C para detener.")
    print("=" * 64 + "\n")

    try:
        cap.iniciar()
    except KeyboardInterrupt:
        print("\n[IDS] Detenido por el usuario.")
        return

    # Si la captura termino sola, fue modo PCAP: esperar el forense y los correos.
    if net.get("pcap_file"):
        print("\n[IDS] PCAP procesado. Completando forense y enviando correos...")
        forense.esperar()
        notificador.esperar()
        print("[IDS] Demo finalizada. Revisa Mailtrap y el dashboard.")


def _cli():
    parser = argparse.ArgumentParser(description="IDS - Sistema de Deteccion de Intrusos")
    parser.add_argument("--pcap", metavar="ARCHIVO",
                        help="Leer de un archivo .pcap (modo demo) en vez de capturar en vivo")
    args = parser.parse_args()
    main(pcap=args.pcap)


if __name__ == "__main__":
    _cli()
