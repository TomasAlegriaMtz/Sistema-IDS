from __future__ import annotations

import ipaddress
import os
import time
from pathlib import Path

import requests

from src.config_loader import load_blacklist_manual, BLACKLIST_MANUAL_FILE
from src import firewall

from src.paths import BASE_DIR

class ModuloThreatIntel:
    def __init__(self, settings: dict, notificador, forense=None, reporter=None,
                 protegidas=None):
        self.notificador = notificador
        self.forense = forense
        self.reporter = reporter
        self.protegidas = protegidas or set()
        ti = settings.get("threat_intel", {}) or {}
        self.feed_url = ti.get(
            "feodo_url", "https://feodotracker.abuse.ch/downloads/ipblocklist.csv"
        )
        self.cache_file = BASE_DIR / ti.get("cache_file", "config/blacklist.cache")
        self.cooldown = (settings.get("alerts", {}) or {}).get("cooldown_seconds", 300)

        self._ultima_alerta = {}
        self._feed = {}
        self._manual = {}
        self.blacklist = {}

        self._last_check = 0.0
        self._manual_mtime = self._mtime()

        self._cargar_feed()
        self._cargar_manual()
        self._rebuild()
        print(f"[threat-intel] Lista negra lista: {len(self.blacklist)} IPs peligrosas.")

    @staticmethod
    def _es_ip(texto: str) -> bool:
        try:
            ipaddress.ip_address(texto)
            return True
        except ValueError:
            return False

    def _mtime(self):
        try:
            return os.path.getmtime(BLACKLIST_MANUAL_FILE)
        except OSError:
            return 0

    def _rebuild(self):
        self.blacklist = {**self._feed, **self._manual}

    def _cargar_feed(self):
        texto = None
        try:
            r = requests.get(self.feed_url, timeout=15)
            r.raise_for_status()
            texto = r.text
            self.cache_file.write_text(texto, encoding="utf-8")
            print("[threat-intel] Feed de abuse.ch descargado y cacheado.")
        except Exception as e:
            print(f"[threat-intel] No se pudo descargar el feed ({e}).")
            if self.cache_file.exists():
                texto = self.cache_file.read_text(encoding="utf-8")
                print("[threat-intel] Usando la cache local del feed.")
        if not texto:
            return
        for linea in texto.splitlines():
            linea = linea.strip()
            if not linea or linea.startswith("#"):
                continue
            partes = [p.strip().strip('"') for p in linea.split(",")]
            if len(partes) >= 6 and self._es_ip(partes[1]):
                self._feed[partes[1]] = f"{partes[5] or 'Malware'} (Botnet/C2)"
            elif self._es_ip(partes[0]):
                self._feed[partes[0]] = "Botnet/C2 (malware)"

    def _cargar_manual(self):
        self._manual = {}
        for e in load_blacklist_manual():
            self._manual[e["ip"]] = e.get("desc") or "Lista negra manual"

    def _maybe_reload(self):
        ahora = time.time()
        if ahora - self._last_check < 2:
            return
        self._last_check = ahora
        m = self._mtime()
        if m != self._manual_mtime:
            self._manual_mtime = m
            try:
                self._cargar_manual()
                self._rebuild()
                print(f"[threat-intel] Lista negra recargada: {len(self.blacklist)} IPs.")
            except Exception as ex:
                print(f"[threat-intel] Error al recargar lista negra: {ex}")

    def _en_cooldown(self, clave: str) -> bool:
        ahora = time.time()
        if ahora - self._ultima_alerta.get(clave, 0) < self.cooldown:
            return True
        self._ultima_alerta[clave] = ahora
        return False

    def handler(self, evento: dict, pkt):
        self._maybe_reload()
        dst_ip = evento.get("dst_ip")
        src_ip = evento.get("src_ip")

        if dst_ip in self.blacklist:
            ip_mala = dst_ip
        elif src_ip in self.blacklist:
            ip_mala = src_ip
        else:
            return

        if self._en_cooldown(ip_mala):
            return

        self._alertar(evento, ip_mala, self.blacklist[ip_mala])

    def _alertar(self, evento, ip_mala, riesgo):
        asunto = f"[IDS] ALERTA DE EMERGENCIA - IP peligrosa detectada ({ip_mala})"
        cuerpo = (
            "Se detecto trafico relacionado con una IP catalogada como PELIGROSA.\n\n"
            f"  IP peligrosa     : {ip_mala}\n"
            f"  Riesgo           : {riesgo}\n"
            f"  Equipo de origen : {evento.get('src_ip')}  (MAC {evento.get('src_mac')})\n"
            f"  Destino          : {evento.get('dst_ip')}\n"
            f"  Protocolo        : {evento.get('proto')}  (puerto {evento.get('dport')})\n\n"
            "ACCION RECOMENDADA: aislar el equipo de origen de la red y\n"
            "revisar una posible infeccion por malware.\n"
        )
        print(f"[!!!] EMERGENCIA: IP peligrosa {ip_mala}  ->  {riesgo}")
        self.notificador.enviar(asunto, cuerpo)
        if self.reporter:
            self.reporter.registrar_alerta(
                "emergencia", f"IP peligrosa {ip_mala}: {riesgo}", ip_mala, cuerpo
            )

        firewall.bloquear(ip_mala, self.protegidas)
        if self.forense:
            self.forense.investigar(ip_mala, evento)
