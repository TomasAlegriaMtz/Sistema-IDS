"""
capture.py - Modulo de Captura (el corazon del IDS)
===================================================

Usa Scapy para capturar paquetes en vivo (o desde un archivo .pcap) y
extrae de cada uno los datos relevantes de varias capas del modelo OSI:

    Capa 2 (Enlace):     MAC origen / destino
    Capa 3 (Red):        IP origen / destino
    Capa 4 (Transporte): protocolo y puertos
    Capa 7 (Aplicacion): consultas DNS y peticiones HTTP (sitios visitados)

Cada paquete se transforma en un diccionario "evento" y se entrega a los
manejadores (handlers) que se hayan registrado. Asi los demas modulos
(listas blancas, threat intel, monitoreo...) solo se "suscriben" a los
eventos sin preocuparse por los detalles de la captura.
"""
from __future__ import annotations

from scapy.all import sniff, Ether, IP, IPv6, TCP, UDP, ARP, DNS, DNSQR

# La capa HTTP es opcional segun la version de Scapy; si no esta, seguimos
# funcionando solo con DNS (que de todas formas es la fuente principal).
try:
    from scapy.layers.http import HTTPRequest
    _HTTP_DISPONIBLE = True
except Exception:
    _HTTP_DISPONIBLE = False

# Numeros de protocolo de la Capa 3 -> nombre legible
PROTOCOLOS = {1: "ICMP", 6: "TCP", 17: "UDP"}


def direcciones_propias():
    """
    Devuelve (ips, macs) de las interfaces del PROPIO equipo (el sensor).
    Sirve para que el IDS no se marque a si mismo como intruso, sin tener
    que ponerse en la lista blanca.
    """
    ips, macs = set(), set()
    try:
        from scapy.all import get_if_list, get_if_addr, get_if_hwaddr
        for iface in get_if_list():
            try:
                ip = get_if_addr(iface)
                if ip and ip != "0.0.0.0":
                    ips.add(ip)
            except Exception:
                pass
            try:
                mac = get_if_hwaddr(iface)
                if mac and mac != "00:00:00:00:00:00":
                    macs.add(mac.lower())
            except Exception:
                pass
    except Exception:
        pass
    return ips, macs


def detectar_gateway():
    """Devuelve la IP del gateway por defecto (para nunca bloquearlo en modo IPS)."""
    try:
        from scapy.all import conf
        gw = conf.route.route("8.8.8.8")[2]
        return gw if gw and gw != "0.0.0.0" else None
    except Exception:
        return None


def parse_packet(pkt) -> dict:
    """
    Convierte un paquete de Scapy en un diccionario "evento" uniforme.
    Si una capa no existe en el paquete, su campo queda en None.
    """
    evento = {
        "src_mac": None, "dst_mac": None,   # Capa 2
        "src_ip": None,  "dst_ip": None,    # Capa 3
        "proto": None,                      # nombre del protocolo (TCP/UDP/..)
        "sport": None,   "dport": None,     # Capa 4
        "domain": None,                     # dominio (DNS) o Host (HTTP)
        "kind": None,                       # "dns", "http", "arp" u otro
    }

    # --- Capa 2: Ethernet (MAC) ---
    if Ether in pkt:
        evento["src_mac"] = pkt[Ether].src.lower()
        evento["dst_mac"] = pkt[Ether].dst.lower()

    # --- Capa 3: IP (v4 o v6) ---
    if IP in pkt:
        evento["src_ip"] = pkt[IP].src
        evento["dst_ip"] = pkt[IP].dst
        evento["proto"] = PROTOCOLOS.get(pkt[IP].proto, str(pkt[IP].proto))
    elif IPv6 in pkt:
        evento["src_ip"] = pkt[IPv6].src
        evento["dst_ip"] = pkt[IPv6].dst

    # --- ARP: util para detectar equipos nuevos en la red local ---
    if ARP in pkt:
        evento["src_ip"] = evento["src_ip"] or pkt[ARP].psrc
        evento["kind"] = evento["kind"] or "arp"

    # --- Capa 4: puertos TCP / UDP ---
    if TCP in pkt:
        evento["sport"], evento["dport"] = pkt[TCP].sport, pkt[TCP].dport
    elif UDP in pkt:
        evento["sport"], evento["dport"] = pkt[UDP].sport, pkt[UDP].dport

    # --- Capa 7: consulta DNS (solo CONSULTAS qr=0, no respuestas del server) ---
    if DNSQR in pkt and DNS in pkt and pkt[DNS].qr == 0:
        try:
            evento["domain"] = pkt[DNSQR].qname.decode(errors="ignore").rstrip(".")
            evento["kind"] = "dns"
        except Exception:
            pass

    # --- Capa 7: peticion HTTP (cabecera Host) ---
    if _HTTP_DISPONIBLE and pkt.haslayer(HTTPRequest):
        try:
            host = pkt[HTTPRequest].Host
            if host:
                evento["domain"] = host.decode() if isinstance(host, bytes) else host
                evento["kind"] = "http"
        except Exception:
            pass

    return evento


class Capturador:
    """
    Captura paquetes y los reparte a los handlers registrados.

    Uso:
        cap = Capturador(settings)
        cap.registrar(mi_handler)   # mi_handler(evento, pkt)
        cap.iniciar()
    """

    def __init__(self, settings: dict):
        net = settings.get("network", {}) or {}
        self.interface = net.get("interface", "eth0")
        self.pcap_file = net.get("pcap_file")   # si tiene valor -> modo demo
        self.handlers = []

    def registrar(self, handler):
        """Registra una funcion que recibira cada evento: handler(evento, pkt)."""
        self.handlers.append(handler)

    def _procesar(self, pkt):
        """Callback de Scapy: debe ser RAPIDO (solo clasifica y reparte)."""
        evento = parse_packet(pkt)
        for handler in self.handlers:
            try:
                handler(evento, pkt)
            except Exception as e:
                print(f"[error en handler] {e}")

    def _interfaz_auto(self):
        """Detecta la interfaz por la que sale el trafico a Internet."""
        try:
            from scapy.all import conf
            iface = conf.route.route("8.8.8.8")[0]
            return iface or None
        except Exception:
            return None

    def iniciar(self):
        """Arranca la captura: desde .pcap (demo) o en vivo (interfaz)."""
        if self.pcap_file:
            print(f"[captura] Modo DEMO, leyendo archivo: {self.pcap_file}")
            sniff(offline=self.pcap_file, prn=self._procesar, store=0)
            return

        iface = self.interface
        if iface in (None, "", "auto"):
            iface = self._interfaz_auto()
        if iface:
            print(f"[captura] Escuchando EN VIVO en: {iface}")
            sniff(iface=iface, prn=self._procesar, store=0)
        else:
            print("[captura] Escuchando EN VIVO (interfaz por defecto del sistema)")
            sniff(prn=self._procesar, store=0)


# ---------------------------------------------------------------------------
# Prueba manual:  sudo ./venv/bin/python3 -m src.capture
# Imprime un resumen de cada paquete que pase por la interfaz.
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import sys
    from pathlib import Path

    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from src.config_loader import load_settings

    settings = load_settings()
    cap = Capturador(settings)

    def mostrar(evento, pkt):
        l2 = f"{evento['src_mac']} -> {evento['dst_mac']}" if evento["src_mac"] else "-"
        if evento["src_ip"]:
            l3 = f"{evento['src_ip']} -> {evento['dst_ip']}"
            if evento["proto"]:
                l3 += f" ({evento['proto']}"
                if evento["dport"]:
                    l3 += f" :{evento['dport']}"
                l3 += ")"
        else:
            l3 = "(sin IP)"
        extra = f"   <<{evento['kind'].upper()}: {evento['domain']}>>" \
            if evento["domain"] else ""
        print(f"L2[{l2}]  L3[{l3}]{extra}")

    cap.registrar(mostrar)
    print("Capturando paquetes... (presiona Ctrl+C para detener)\n")
    try:
        cap.iniciar()
    except KeyboardInterrupt:
        print("\n[captura] Detenida por el usuario.")
