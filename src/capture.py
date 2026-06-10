from __future__ import annotations

from scapy.all import sniff, Ether, IP, IPv6, TCP, UDP, ARP, DNS, DNSQR

try:
    from scapy.layers.http import HTTPRequest
    _HTTP_DISPONIBLE = True
except Exception:
    _HTTP_DISPONIBLE = False

PROTOCOLOS = {1: "ICMP", 6: "TCP", 17: "UDP"}

def direcciones_propias():
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
    try:
        from scapy.all import conf
        gw = conf.route.route("8.8.8.8")[2]
        return gw if gw and gw != "0.0.0.0" else None
    except Exception:
        return None

def parse_packet(pkt) -> dict:
    evento = {
        "src_mac": None, "dst_mac": None,
        "src_ip": None,  "dst_ip": None,
        "proto": None,
        "sport": None,   "dport": None,
        "domain": None,
        "kind": None,
    }

    if Ether in pkt:
        evento["src_mac"] = pkt[Ether].src.lower()
        evento["dst_mac"] = pkt[Ether].dst.lower()

    if IP in pkt:
        evento["src_ip"] = pkt[IP].src
        evento["dst_ip"] = pkt[IP].dst
        evento["proto"] = PROTOCOLOS.get(pkt[IP].proto, str(pkt[IP].proto))
    elif IPv6 in pkt:
        evento["src_ip"] = pkt[IPv6].src
        evento["dst_ip"] = pkt[IPv6].dst

    if ARP in pkt:
        evento["src_ip"] = evento["src_ip"] or pkt[ARP].psrc
        evento["kind"] = evento["kind"] or "arp"

    if TCP in pkt:
        evento["sport"], evento["dport"] = pkt[TCP].sport, pkt[TCP].dport
    elif UDP in pkt:
        evento["sport"], evento["dport"] = pkt[UDP].sport, pkt[UDP].dport

    if DNSQR in pkt and DNS in pkt and pkt[DNS].qr == 0:
        try:
            evento["domain"] = pkt[DNSQR].qname.decode(errors="ignore").rstrip(".")
            evento["kind"] = "dns"
        except Exception:
            pass

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
    def __init__(self, settings: dict):
        net = settings.get("network", {}) or {}
        self.interface = net.get("interface", "eth0")
        self.handlers = []

    def registrar(self, handler):
        self.handlers.append(handler)

    def _procesar(self, pkt):
        evento = parse_packet(pkt)
        for handler in self.handlers:
            try:
                handler(evento, pkt)
            except Exception as e:
                print(f"[error en handler] {e}")

    def _interfaz_auto(self):
        try:
            from scapy.all import conf
            iface = conf.route.route("8.8.8.8")[0]
            return iface or None
        except Exception:
            return None

    def iniciar(self):
        iface = self.interface
        if iface in (None, "", "auto"):
            iface = self._interfaz_auto()
        if iface:
            print(f"[captura] Escuchando EN VIVO en: {iface}")
            sniff(iface=iface, prn=self._procesar, store=0)
        else:
            print("[captura] Escuchando EN VIVO (interfaz por defecto del sistema)")
            sniff(prn=self._procesar, store=0)

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
        extra = f"   <<{evento['kind'].upper()}: {evento['domain']}>>"            if evento["domain"] else ""
        print(f"L2[{l2}]  L3[{l3}]{extra}")

    cap.registrar(mostrar)
    print("Capturando paquetes... (presiona Ctrl+C para detener)\n")
    try:
        cap.iniciar()
    except KeyboardInterrupt:
        print("\n[captura] Detenida por el usuario.")
