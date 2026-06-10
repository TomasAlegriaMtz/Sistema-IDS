from __future__ import annotations

import ipaddress
import time

class ModuloMonitoreoSitios:
    def __init__(self, settings: dict, reporter, ventana_dedup: int = 5):
        self.reporter = reporter
        self.ventana = ventana_dedup
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
        dominio = evento.get("domain")
        tipo = evento.get("kind")
        if not dominio or tipo not in ("dns", "http"):
            return

        src_ip = evento.get("src_ip")
        if not self._es_local(src_ip):
            return

        clave = (src_ip, dominio)
        ahora = time.time()
        if ahora - self._reciente.get(clave, 0) < self.ventana:
            return
        self._reciente[clave] = ahora

        self.reporter.registrar_visita(src_ip, dominio, tipo)
        print(f"[SITIO] {src_ip:<15} -> {dominio}  ({tipo})")
