"""
make_demo_pcap.py - Genera el archivo de demostracion (tools/demo.pcap)
=======================================================================
Fabrica con Scapy un escenario de trafico que, al reproducirlo, dispara
LOS 4 MODULOS del IDS de forma reproducible y SEGURA: los paquetes solo se
ESCRIBEN en un archivo .pcap; NUNCA se envian a la red.

Escenario incluido:
  1. Cliente AUTORIZADO (10.0.2.15) consulta varios sitios por DNS
     -> Modulo 2 (monitoreo) los registra; Modulo 1 NO alerta (esta en lista).
  2. Equipo NO autorizado (10.0.2.66) genera trafico
     -> Modulo 1 (listas blancas) dispara alerta de intruso.
  3. El cliente abre una conexion a una IP PELIGROSA real (feed de abuse.ch)
     -> Modulo 3 (emergencia) + Modulo 4 (forense Whois/AbuseIPDB).

Para que el Modulo 3 reconozca la IP sin depender del feed del dia, esa IP
tambien se agrega a config/blacklist_manual.txt.

Uso:
    ./venv/bin/python3 tools/make_demo_pcap.py
Luego:
    sudo ./venv/bin/python3 -m src.main --pcap tools/demo.pcap
"""
import ipaddress
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import requests
from scapy.all import Ether, IP, UDP, TCP, DNS, DNSQR, wrpcap

from src.paths import BASE_DIR
PCAP = BASE_DIR / "tools" / "demo.pcap"
MANUAL = BASE_DIR / "config" / "blacklist_manual.txt"

# --- Actores del escenario ---
MAC_CLIENTE = "08:00:27:aa:bb:15"
IP_CLIENTE = "10.0.2.15"           # autorizado (esta en whitelist.yaml)
MAC_INTRUSO = "de:ad:be:ef:00:66"
IP_INTRUSO = "10.0.2.66"           # NO autorizado
MAC_GW = "52:54:00:12:35:02"
IP_DNS = "10.0.2.3"

SITIOS = ["wikipedia.org", "github.com", "unam.mx", "google.com",
          "cloudflare.com", "mozilla.org", "stackoverflow.com"]
FALLBACK_IP = ("203.0.113.66", "DemoBot")   # respaldo (rango de documentacion)


def _es_ipv4(s: str) -> bool:
    try:
        return isinstance(ipaddress.ip_address(s), ipaddress.IPv4Address)
    except ValueError:
        return False


def elegir_ip_peligrosa():
    """Toma la primera IP real del feed de Feodo; si no hay red, usa respaldo."""
    try:
        r = requests.get(
            "https://feodotracker.abuse.ch/downloads/ipblocklist.csv", timeout=15
        )
        r.raise_for_status()
        for linea in r.text.splitlines():
            linea = linea.strip()
            if not linea or linea.startswith("#"):
                continue
            partes = [p.strip().strip('"') for p in linea.split(",")]
            if len(partes) >= 6 and _es_ipv4(partes[1]):
                return partes[1], (partes[5] or "Malware")
    except Exception as e:
        print(f"[demo] No se pudo bajar el feed ({e}); uso IP de respaldo.")
    return FALLBACK_IP


def asegurar_en_blacklist(ip, familia):
    """Garantiza que la IP peligrosa este en la lista negra manual."""
    contenido = MANUAL.read_text(encoding="utf-8") if MANUAL.exists() else ""
    if ip in contenido:
        return
    with MANUAL.open("a", encoding="utf-8") as fh:
        fh.write("\n# Agregada automaticamente por la demo:\n")
        fh.write(f"{ip},{familia} (Botnet/C2) - escenario demo\n")
    print(f"[demo] {ip} agregada a {MANUAL.name}")


def consulta_dns(mac_src, ip_src, dominio):
    return (Ether(src=mac_src, dst=MAC_GW) /
            IP(src=ip_src, dst=IP_DNS) /
            UDP(sport=40000, dport=53) /
            DNS(rd=1, qd=DNSQR(qname=dominio)))


def construir():
    ip_mala, familia = elegir_ip_peligrosa()
    asegurar_en_blacklist(ip_mala, familia)

    paquetes = []
    # (1) Cliente autorizado navega -> Modulo 2
    for d in SITIOS:
        paquetes.append(consulta_dns(MAC_CLIENTE, IP_CLIENTE, d))
    # (2) Equipo NO autorizado genera trafico -> Modulo 1
    paquetes.append(consulta_dns(MAC_INTRUSO, IP_INTRUSO, "host-desconocido.local"))
    # (3) Conexion a IP peligrosa -> Modulo 3 + 4
    paquetes.append(
        Ether(src=MAC_CLIENTE, dst=MAC_GW) /
        IP(src=IP_CLIENTE, dst=ip_mala) /
        TCP(sport=44321, dport=443, flags="S")
    )

    wrpcap(str(PCAP), paquetes)
    print(f"[demo] {len(paquetes)} paquetes escritos en {PCAP}")
    print(f"[demo] IP peligrosa del escenario: {ip_mala}  ({familia})")
    print("[demo] Ahora corre:")
    print("       sudo ./venv/bin/python3 -m src.main --pcap tools/demo.pcap")


if __name__ == "__main__":
    construir()
