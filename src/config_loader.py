from __future__ import annotations

import os
import socket
from pathlib import Path

import yaml
from dotenv import load_dotenv

from src.paths import BASE_DIR

WHITELIST_FILE = BASE_DIR / "config" / "whitelist.yaml"
BLACKLIST_MANUAL_FILE = BASE_DIR / "config" / "blacklist_manual.txt"
ENV_FILE = BASE_DIR / ".env"

def load_secrets() -> dict:
    load_dotenv(ENV_FILE, override=True)

    requeridas = ["SMTP_HOST", "SMTP_PORT", "SMTP_USER", "SMTP_PASSWORD"]
    secrets = {clave: os.getenv(clave) for clave in requeridas}
    secrets["ABUSEIPDB_API_KEY"] = os.getenv("ABUSEIPDB_API_KEY", "")
    secrets["ALERT_TO"] = os.getenv("ALERT_TO", "")
    secrets["ALERT_FROM"] = os.getenv("ALERT_FROM", "")

    faltantes = [k for k in requeridas if not secrets[k]]
    if faltantes:
        raise RuntimeError(
            "Faltan variables en .env: " + ", ".join(faltantes) + ". "
            "Copia .env.example a .env y rellena los valores."
        )
    return secrets

def _load_yaml(nombre: str) -> dict:
    ruta = BASE_DIR / "config" / nombre
    if not ruta.exists():
        raise FileNotFoundError(f"No se encontro el archivo de config: {ruta}")
    with ruta.open("r", encoding="utf-8") as fh:
        return yaml.safe_load(fh) or {}

def load_settings() -> dict:
    return _load_yaml("settings.yaml")

def load_whitelist() -> dict:
    data = _load_yaml("whitelist.yaml")
    ips: set[str] = set()
    macs: set[str] = set()
    equipos = data.get("authorized", []) or []

    for equipo in equipos:
        if equipo.get("ip"):
            ips.add(str(equipo["ip"]).strip())
        if equipo.get("mac"):
            macs.add(str(equipo["mac"]).strip().lower())

    return {"ips": ips, "macs": macs, "equipos": equipos}

def save_whitelist(equipos: list) -> None:
    with WHITELIST_FILE.open("w", encoding="utf-8") as fh:
        fh.write("# Lista Blanca de equipos autorizados (editable desde el dashboard)\n")
        yaml.safe_dump({"authorized": equipos}, fh, allow_unicode=True, sort_keys=False)

def load_blacklist_manual() -> list:
    entradas = []
    if BLACKLIST_MANUAL_FILE.exists():
        for linea in BLACKLIST_MANUAL_FILE.read_text(encoding="utf-8").splitlines():
            linea = linea.strip()
            if not linea or linea.startswith("#"):
                continue
            partes = [p.strip() for p in linea.split(",", 1)]
            entradas.append({"ip": partes[0], "desc": partes[1] if len(partes) > 1 else ""})
    return entradas

def save_blacklist_manual(entradas: list) -> None:
    lineas = ["# Lista negra MANUAL de IPs (editable desde el dashboard)",
              "# Formato:  IP,descripcion_del_riesgo", ""]
    for e in entradas:
        ip = str(e.get("ip", "")).strip()
        desc = str(e.get("desc", "")).strip()
        if not ip:
            continue
        lineas.append(f"{ip},{desc}" if desc else ip)
    BLACKLIST_MANUAL_FILE.write_text("\n".join(lineas) + "\n", encoding="utf-8")

def update_env(updates: dict) -> None:
    lineas = ENV_FILE.read_text(encoding="utf-8").splitlines() if ENV_FILE.exists() else []
    puestas = set()
    salida = []
    for linea in lineas:
        if "=" in linea and not linea.strip().startswith("#"):
            clave = linea.split("=", 1)[0].strip()
            if clave in updates:
                salida.append(f"{clave}={updates[clave]}")
                puestas.add(clave)
                continue
        salida.append(linea)
    for clave, valor in updates.items():
        if clave not in puestas:
            salida.append(f"{clave}={valor}")
    ENV_FILE.write_text("\n".join(salida) + "\n", encoding="utf-8")

def load_email_config() -> dict:
    load_dotenv(ENV_FILE, override=True)
    s = load_settings()
    pwd = os.getenv("SMTP_PASSWORD", "")
    return {
        "host": os.getenv("SMTP_HOST", ""),
        "port": os.getenv("SMTP_PORT", "2525"),
        "user": os.getenv("SMTP_USER", ""),
        "to": os.getenv("ALERT_TO", "") or (s.get("admin", {}) or {}).get("email", ""),
        "from": os.getenv("ALERT_FROM", "") or (s.get("alerts", {}) or {}).get("from_address", ""),
        "password_set": bool(pwd) and pwd != "cambia_esto",
    }

def detectar_subred() -> str | None:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        import ipaddress
        return str(ipaddress.ip_network(ip + "/24", strict=False))
    except Exception:
        return None

if __name__ == "__main__":
    print("== settings.yaml ==")
    print(load_settings())
    print("\n== whitelist.yaml ==")
    wl = load_whitelist()
    print(f"IPs autorizadas : {sorted(wl['ips'])}")
    print(f"MACs autorizadas: {sorted(wl['macs'])}")
    print("\n== .env ==")
    try:
        load_secrets()
        print("Secretos cargados correctamente (.env OK)")
    except RuntimeError as e:
        print("AVISO:", e)
