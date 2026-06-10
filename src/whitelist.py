from __future__ import annotations

import ipaddress
import os
import time

from src.config_loader import load_whitelist, WHITELIST_FILE
from src import firewall

class ModuloListasBlancas:
    def __init__(self, settings: dict, whitelist: dict, notificador, reporter=None,
                 ips_propias=None, macs_propias=None, protegidas=None):
        self.ips_ok = whitelist["ips"]
        self.macs_ok = whitelist["macs"]
        self.notificador = notificador
        self.reporter = reporter

        self.ips_propias = ips_propias or set()
        self.macs_propias = macs_propias or set()

        self.protegidas = protegidas or set()
        self._last_check = 0.0
        self._wl_mtime = self._mtime()

        net = settings.get("network", {}) or {}
        try:
            self.subred = ipaddress.ip_network(
                net.get("monitored_subnet", "0.0.0.0/0"), strict=False
            )
        except ValueError:
            self.subred = ipaddress.ip_network("0.0.0.0/0")

        self.cooldown = (settings.get("alerts", {}) or {}).get("cooldown_seconds", 300)
        self._ultima_alerta: dict[str, float] = {}

    def _es_local(self, ip: str) -> bool:
        if not ip:
            return False
        try:
            return ipaddress.ip_address(ip) in self.subred
        except ValueError:
            return False

    def _en_cooldown(self, clave: str) -> bool:
        ahora = time.time()
        if ahora - self._ultima_alerta.get(clave, 0) < self.cooldown:
            return True
        self._ultima_alerta[clave] = ahora
        return False

    def _mtime(self):
        try:
            return os.path.getmtime(WHITELIST_FILE)
        except OSError:
            return 0

    def _maybe_reload(self):
        ahora = time.time()
        if ahora - self._last_check < 2:
            return
        self._last_check = ahora
        m = self._mtime()
        if m != self._wl_mtime:
            self._wl_mtime = m
            try:
                wl = load_whitelist()
                self.ips_ok, self.macs_ok = wl["ips"], wl["macs"]
                print("[modulo1] Lista blanca recargada (cambio detectado).")
            except Exception as e:
                print(f"[modulo1] Error al recargar lista blanca: {e}")

    def handler(self, evento: dict, pkt):
        self._maybe_reload()
        src_ip = evento.get("src_ip")
        src_mac = evento.get("src_mac")

        if not self._es_local(src_ip):
            return

        if (src_ip in self.ips_propias) or (src_mac in self.macs_propias):
            return

        if (src_ip in self.ips_ok) or (src_mac in self.macs_ok):
            return

        clave = src_mac or src_ip
        if self._en_cooldown(clave):
            return

        self._alertar(src_ip, src_mac, evento)

    def _alertar(self, src_ip, src_mac, evento):
        asunto = f"[IDS] Equipo NO autorizado en la red: {src_ip}"
        cuerpo = (
            "Se detecto trafico de un equipo que NO esta en la lista blanca.\n\n"
            f"  IP origen   : {src_ip}\n"
            f"  MAC origen  : {src_mac}\n"
            f"  Destino     : {evento.get('dst_ip')}\n"
            f"  Protocolo   : {evento.get('proto')}  (puerto {evento.get('dport')})\n\n"
            "Accion sugerida: si el equipo es legitimo, agregarlo a\n"
            "config/whitelist.yaml; de lo contrario, investigar/bloquear.\n"
        )
        print(f"[!] INTRUSO detectado: {src_ip}  (MAC {src_mac})")
        self.notificador.enviar(asunto, cuerpo)
        if self.reporter:
            self.reporter.registrar_alerta("intruso", asunto, src_ip, cuerpo)

        firewall.bloquear(src_ip, self.protegidas)
