from __future__ import annotations

import threading

import requests
from ipwhois import IPWhois

from src.config_loader import load_secrets

class ModuloForense:
    def __init__(self, settings: dict, notificador, reporter=None):
        self.notificador = notificador
        self.reporter = reporter
        self._threads = []
        try:
            secrets = load_secrets()
            self.abuseipdb_key = secrets.get("ABUSEIPDB_API_KEY", "") or ""
        except Exception:
            self.abuseipdb_key = ""

        if self.abuseipdb_key in ("", "cambia_esto"):
            self.abuseipdb_key = ""

    def investigar(self, ip: str, evento: dict | None = None):
        t = threading.Thread(target=self._investigar, args=(ip, evento), daemon=True)
        t.start()
        self._threads.append(t)

    def esperar(self, timeout: float = 25):
        for t in self._threads:
            t.join(timeout=timeout)

    def _investigar(self, ip, evento):
        print(f"[forense] Investigando IP peligrosa {ip} (Whois + AbuseIPDB)...")
        rdap = self._consultar_rdap(ip)
        abuse = self._consultar_abuseipdb(ip)
        self._enviar_reporte(ip, evento, rdap, abuse)

    def _consultar_rdap(self, ip: str) -> dict:
        datos: dict = {}
        try:
            res = IPWhois(ip).lookup_rdap(depth=1)
            red = res.get("network") or {}
            datos["asn"] = res.get("asn")
            datos["asn_description"] = res.get("asn_description")
            datos["network_name"] = red.get("name")
            datos["country"] = red.get("country") or res.get("asn_country_code")

            abuse_emails, otros = set(), set()
            for obj in (res.get("objects") or {}).values():
                roles = obj.get("roles") or []
                contacto = obj.get("contact") or {}
                correos = [e.get("value") for e in (contacto.get("email") or []) if e.get("value")]
                if "abuse" in roles:
                    abuse_emails.update(correos)
                else:
                    otros.update(correos)
            datos["abuse_emails"] = sorted(abuse_emails) or sorted(otros)
        except Exception as e:
            datos["error"] = str(e)
        return datos

    def _consultar_abuseipdb(self, ip: str) -> dict:
        if not self.abuseipdb_key:
            return {"error": "sin API key (define ABUSEIPDB_API_KEY en .env)"}
        try:
            r = requests.get(
                "https://api.abuseipdb.com/api/v2/check",
                headers={"Key": self.abuseipdb_key, "Accept": "application/json"},
                params={"ipAddress": ip, "maxAgeInDays": 90},
                timeout=15,
            )
            r.raise_for_status()
            d = r.json().get("data", {})
            return {
                "score": d.get("abuseConfidenceScore"),
                "total_reports": d.get("totalReports"),
                "isp": d.get("isp"),
                "domain": d.get("domain"),
                "country": d.get("countryCode"),
            }
        except Exception as e:
            return {"error": str(e)}

    def _enviar_reporte(self, ip, evento, rdap, abuse):
        L = [f"REPORTE FORENSE de la IP peligrosa: {ip}", ""]

        L.append("--- Proveedor / Red (RDAP - Whois) ---")
        if rdap.get("error"):
            L.append(f"  (RDAP no disponible: {rdap['error']})")
        else:
            L.append(f"  ASN            : {rdap.get('asn')}  -  {rdap.get('asn_description')}")
            L.append(f"  Red            : {rdap.get('network_name')}")
            L.append(f"  Pais           : {rdap.get('country')}")
            contactos = rdap.get("abuse_emails") or []
            L.append(f"  Contacto abuso : {', '.join(contactos) if contactos else 'no publicado'}")

        L += ["", "--- Reputacion (AbuseIPDB) ---"]
        if abuse.get("error"):
            L.append(f"  (AbuseIPDB no disponible: {abuse['error']})")
        else:
            L.append(f"  Score de abuso : {abuse.get('score')}/100")
            L.append(f"  Reportes       : {abuse.get('total_reports')}")
            L.append(f"  ISP / dominio  : {abuse.get('isp')} / {abuse.get('domain')}")
            L.append(f"  Pais           : {abuse.get('country')}")

        L += ["", "--- Como reportar este sitio ---"]
        contactos = rdap.get("abuse_emails") or []
        if contactos:
            L.append(f"  1) Envia la queja al contacto de abuso: {contactos[0]}")
        L.append(f"  2) Reporta en AbuseIPDB: https://www.abuseipdb.com/check/{ip}")

        asunto = f"[IDS] Reporte forense de IP peligrosa ({ip})"
        cuerpo = "\n".join(L)
        self.notificador.enviar(asunto, cuerpo)
        if self.reporter:
            self.reporter.registrar_alerta("forense", asunto, ip, cuerpo)
        print(f"[forense] Reporte de {ip} enviado al administrador.")
