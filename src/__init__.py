"""
Paquete principal del IDS.

Modulos:
    config_loader  -> carga de configuracion y secretos
    capture        -> sniffer Scapy + dispatcher (Modulo de captura)
    whitelist      -> Modulo 1: listas blancas L2/L3
    site_monitor   -> Modulo 2: bitacora de sitios (DNS/HTTP)
    threat_intel   -> Modulo 3: deteccion de IPs peligrosas
    forensics      -> Modulo 4: automatizacion forense (Whois/abuse)
    notifier       -> envio de alertas por correo (SMTP)
    reporter       -> persistencia de bitacora (SQLite) y vista CLI
"""

__version__ = "0.1.0"
__license__ = "GPL-3.0-or-later"
