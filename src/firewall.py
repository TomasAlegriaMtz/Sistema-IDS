"""
firewall.py - Modo IPS (bloqueo automatico)
===========================================
Cuando el modo IPS esta ACTIVO, el IDS no solo detecta: BLOQUEA en el
firewall del sistema operativo las IPs de intrusos o IPs peligrosas.

  * Linux:   iptables           (requiere root)
  * Windows: netsh advfirewall  (requiere administrador)

El estado (activo/inactivo) y la lista de IPs bloqueadas se guardan en
archivos JSON dentro de logs/, para que el dashboard (que puede ser otro
proceso) pueda encender/apagar el modo y ver/limpiar los bloqueos.

SEGURIDAD:
  * Por defecto el modo IPS viene DESACTIVADO.
  * NUNCA bloquea IPs "protegidas" (el propio equipo, el gateway, las
    autorizadas) para no dejar al sensor sin red.
"""
from __future__ import annotations

import json
import os
import subprocess
import threading

from src.paths import BASE_DIR

ES_WINDOWS = os.name == "nt"
ESTADO_FILE = BASE_DIR / "logs" / "ips_state.json"
BLOQUEADAS_FILE = BASE_DIR / "logs" / "ips_blocked.json"
PREFIJO = "IDS-block"

_lock = threading.Lock()


def _leer_json(ruta, defecto):
    try:
        return json.loads(ruta.read_text(encoding="utf-8"))
    except Exception:
        return defecto


def _escribir_json(ruta, datos):
    ruta.parent.mkdir(parents=True, exist_ok=True)
    ruta.write_text(json.dumps(datos), encoding="utf-8")


def esta_activo() -> bool:
    """True si el modo IPS esta encendido (por defecto False)."""
    return bool(_leer_json(ESTADO_FILE, {}).get("enabled", False))


def set_activo(valor: bool):
    _escribir_json(ESTADO_FILE, {"enabled": bool(valor)})


def listar_bloqueadas() -> list:
    return _leer_json(BLOQUEADAS_FILE, [])


def bloquear(ip: str, protegidas=None) -> bool:
    """Bloquea una IP en el firewall, SOLO si el modo IPS esta activo."""
    if not ip or not esta_activo():
        return False
    if protegidas and ip in protegidas:
        print(f"[IPS] {ip} esta protegida; no se bloquea.")
        return False
    with _lock:
        bloqueadas = listar_bloqueadas()
        if ip in bloqueadas:
            return False
        if _aplicar_regla(ip):
            bloqueadas.append(ip)
            _escribir_json(BLOQUEADAS_FILE, bloqueadas)
            print(f"[IPS] IP BLOQUEADA en el firewall: {ip}")
            return True
    return False


def _aplicar_regla(ip: str) -> bool:
    try:
        if ES_WINDOWS:
            subprocess.run(["netsh", "advfirewall", "firewall", "add", "rule",
                            f"name={PREFIJO}-{ip}", "dir=in", "action=block",
                            f"remoteip={ip}"], capture_output=True, check=False)
            subprocess.run(["netsh", "advfirewall", "firewall", "add", "rule",
                            f"name={PREFIJO}-{ip}-out", "dir=out", "action=block",
                            f"remoteip={ip}"], capture_output=True, check=False)
        else:
            subprocess.run(["iptables", "-I", "INPUT", "-s", ip, "-j", "DROP"],
                           capture_output=True, check=False)
            subprocess.run(["iptables", "-I", "OUTPUT", "-d", ip, "-j", "DROP"],
                           capture_output=True, check=False)
        return True
    except Exception as e:
        print(f"[IPS] Error al bloquear {ip}: {e}")
        return False


def limpiar() -> int:
    """Elimina todas las reglas de bloqueo creadas por el IDS."""
    with _lock:
        bloqueadas = listar_bloqueadas()
        for ip in bloqueadas:
            try:
                if ES_WINDOWS:
                    subprocess.run(["netsh", "advfirewall", "firewall", "delete",
                                    "rule", f"name={PREFIJO}-{ip}"],
                                   capture_output=True, check=False)
                    subprocess.run(["netsh", "advfirewall", "firewall", "delete",
                                    "rule", f"name={PREFIJO}-{ip}-out"],
                                   capture_output=True, check=False)
                else:
                    subprocess.run(["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"],
                                   capture_output=True, check=False)
                    subprocess.run(["iptables", "-D", "OUTPUT", "-d", ip, "-j", "DROP"],
                                   capture_output=True, check=False)
            except Exception:
                pass
        n = len(bloqueadas)
        _escribir_json(BLOQUEADAS_FILE, [])
        print(f"[IPS] {n} reglas de bloqueo eliminadas.")
        return n
