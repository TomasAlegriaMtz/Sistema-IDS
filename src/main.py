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

def main(auto: bool = False):
    print("=" * 64)
    print("  IDS - Sistema de Deteccion de Intrusos")
    print("=" * 64)

    settings = load_settings()
    whitelist = load_whitelist()

    net = settings.setdefault("network", {})
    if auto:
        net["interface"] = "auto"
    if auto or net.get("monitored_subnet") in (None, "", "auto"):
        detectada = detectar_subred()
        if detectada:
            net["monitored_subnet"] = detectada
            print(f"  Subred autodetectada   : {detectada}")

    print(f"  Interfaz               : {net.get('interface')}")
    print(f"  Subred vigilada        : {net.get('monitored_subnet')}")
    print(f"  Admin (recibe alertas) : {settings.get('admin', {}).get('email')}")
    print(f"  Equipos autorizados    : {len(whitelist['equipos'])}")
    print("-" * 64)

    notificador = Notificador(settings)
    reporter = Reporter(settings)

    forense = ModuloForense(settings, notificador, reporter=reporter)

    ips_propias, macs_propias = set(), set()
    if net.get("ignorar_equipo_local", True):
        ips_propias, macs_propias = direcciones_propias()
        print(f"  Equipo propio (ignorado): {len(ips_propias)} IPs / {len(macs_propias)} MACs")

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

def _cli():
    parser = argparse.ArgumentParser(
        description="IDS - Sistema de Deteccion de Intrusos (captura en vivo)")
    parser.add_argument("--auto", action="store_true",
                        help="Autodetecta la interfaz y la subred (recomendado)")
    args = parser.parse_args()
    main(auto=args.auto)

if __name__ == "__main__":
    _cli()
