"""
whitelist.py - Modulo 1: Listas Blancas (Capa 2 y 3)
====================================================
Valida cada paquete contra la lista de equipos autorizados
(config/whitelist.yaml).

Regla de negocio:
  * Un equipo esta AUTORIZADO si su IP (Capa 3) O su MAC (Capa 2) aparece
    en la lista blanca.
  * Si un equipo de la red LOCAL (dentro de monitored_subnet) NO esta en la
    lista y genera trafico, se dispara una alerta INMEDIATA al administrador.

Concepto IAA (Identificacion, Autenticacion, Autorizacion):
  - Identificacion = la IP/MAC que dice tener el equipo.
  - Autenticacion  = se compara contra la lista blanca (fuente de verdad).
  - Autorizacion   = si coincide, se permite; si no, se alerta.
  El correo del administrador se define en config/settings.yaml (no en codigo).

Anti-spam: enfriamiento (cooldown) por origen para no enviar mil correos
por el mismo intruso.
"""
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
        # IPs/MACs del propio equipo (el sensor): nunca se marcan como intruso.
        self.ips_propias = ips_propias or set()
        self.macs_propias = macs_propias or set()
        # IPs que NUNCA se bloquean en modo IPS (propias, gateway, autorizadas).
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
        self._ultima_alerta: dict[str, float] = {}   # {clave: timestamp}

    # -------------------- helpers --------------------
    def _es_local(self, ip: str) -> bool:
        """True si la IP pertenece a la subred que estamos vigilando."""
        if not ip:
            return False
        try:
            return ipaddress.ip_address(ip) in self.subred
        except ValueError:
            return False

    def _en_cooldown(self, clave: str) -> bool:
        """Evita repetir la alerta del mismo origen dentro del periodo."""
        ahora = time.time()
        if ahora - self._ultima_alerta.get(clave, 0) < self.cooldown:
            return True
        self._ultima_alerta[clave] = ahora
        return False

    # -------------------- recarga en caliente --------------------
    def _mtime(self):
        try:
            return os.path.getmtime(WHITELIST_FILE)
        except OSError:
            return 0

    def _maybe_reload(self):
        """Recarga la lista blanca si el archivo cambio (editado desde la web)."""
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

    # -------------------- handler principal --------------------
    def handler(self, evento: dict, pkt):
        """Se ejecuta por cada paquete capturado (lo registra el Capturador)."""
        self._maybe_reload()
        src_ip = evento.get("src_ip")
        src_mac = evento.get("src_mac")

        # Solo evaluamos equipos de la red LOCAL como origen
        # (asi no marcamos a los servidores de Internet).
        if not self._es_local(src_ip):
            return

        # El propio equipo que ejecuta el IDS (el sensor) NO se alerta a si mismo.
        if (src_ip in self.ips_propias) or (src_mac in self.macs_propias):
            return

        # Autorizado si su IP o su MAC esta en la lista blanca.
        if (src_ip in self.ips_ok) or (src_mac in self.macs_ok):
            return

        # Intruso. Cooldown por origen (MAC si la hay; si no, IP).
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
        # Modo IPS (si esta activo): bloquear al intruso en el firewall.
        firewall.bloquear(src_ip, self.protegidas)
