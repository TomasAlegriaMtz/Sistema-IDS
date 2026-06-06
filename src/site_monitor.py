"""
site_monitor.py - Modulo 2: Monitoreo de Sitios (Reporte)
=========================================================
Registra en tiempo real los nombres de dominio que consultan los equipos
de la red local, a partir de:
  * Consultas DNS (qname)
  * Peticiones HTTP (cabecera Host)

Cada visita se guarda en la bitacora (SQLite, via Reporter) y se muestra
en consola al instante. DNS es la fuente principal porque es visible
incluso para sitios HTTPS: no se ve el contenido, pero si el dominio.

Solo se registran los equipos de la red LOCAL (monitored_subnet); asi el
reporte refleja "lo que visitan los usuarios de la red", no el trafico
reenviado hacia Internet.
"""
from __future__ import annotations

import ipaddress
import time


class ModuloMonitoreoSitios:
    def __init__(self, settings: dict, reporter, ventana_dedup: int = 5):
        self.reporter = reporter
        self.ventana = ventana_dedup          # seg. para no duplicar lo mismo
        self._reciente: dict[tuple, float] = {}

        net = settings.get("network", {}) or {}
        try:
            self.subred = ipaddress.ip_network(
                net.get("monitored_subnet", "0.0.0.0/0"), strict=False
            )
        except ValueError:
            self.subred = ipaddress.ip_network("0.0.0.0/0")

    def _es_local(self, ip: str) -> bool:
        if not ip:
            return False
        try:
            return ipaddress.ip_address(ip) in self.subred
        except ValueError:
            return False

    def handler(self, evento: dict, pkt):
        """Se ejecuta por cada paquete (lo registra el Capturador)."""
        dominio = evento.get("domain")
        tipo = evento.get("kind")
        if not dominio or tipo not in ("dns", "http"):
            return

        src_ip = evento.get("src_ip")
        if not self._es_local(src_ip):
            return

        # Anti-duplicados: misma (IP, dominio) en una ventana corta -> ignorar.
        clave = (src_ip, dominio)
        ahora = time.time()
        if ahora - self._reciente.get(clave, 0) < self.ventana:
            return
        self._reciente[clave] = ahora

        self.reporter.registrar_visita(src_ip, dominio, tipo)
        print(f"[SITIO] {src_ip:<15} -> {dominio}  ({tipo})")
