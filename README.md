# 🛡️ Sistema IDS/IPS Institucional

![Python](https://img.shields.io/badge/Python-3.11+-3776AB?logo=python&logoColor=white)
![Scapy](https://img.shields.io/badge/Scapy-captura%20de%20paquetes-orange)
![Plataforma](https://img.shields.io/badge/SO-Linux%20%7C%20Windows-informational)

Sistema de **Detección y Prevención de Intrusos (IDS/IPS)** escrito en **Python** sobre **Scapy**.
Monitorea la red **EN VIVO** en las **Capas 2/3/7** del modelo OSI: registra la actividad,
detecta amenazas, **alerta por correo** y puede **bloquear automáticamente** (modo IPS),
todo desde un **dashboard web** en tiempo real.

> Proyecto académico de ciberseguridad. Licencia **GNU GPL v3** (en el espíritu de Stallman & Torvalds 🐧).

---

## Características

### Módulos principales
| Módulo | Qué hace |
|---|---|
| 🧾 **Listas Blancas (Capa 2 y 3)** | Valida IP/MAC autorizadas; alerta inmediata por correo ante equipos no registrados (concepto **IAA**). |
| 🌐 **Monitoreo de Sitios** | Bitácora en tiempo real de los dominios (DNS/HTTP) que visita la red. |
| ☣️ **IPs Peligrosas (Threat Intel)** | Lista negra de botnets/malware (feed de **abuse.ch**); "Alerta de Emergencia" con el tipo de riesgo. |
| 🔎 **Automatización Forense** | Consulta **Whois/RDAP + AbuseIPDB** de la IP peligrosa y envía el contacto de abuso al administrador. |

### Extras
- 🖥️ **Dashboard web tipo SOC**: KPIs, gráficas, búsqueda y filtros por severidad, gestión de listas y correo **en caliente**.
- 🚫 **Modo IPS**: bloqueo automático en el firewall (`iptables` / Firewall de Windows), activable con un botón (desactivado por defecto).
- 📦 **Ejecutable `.exe`** (Windows) — doble clic, sin instalar Python.
- 📧 **Alertas por correo (SMTP)** configurables y probables desde la web.
- 🛰️ **Autodetección** de interfaz y subred + **auto-ignorado** del propio sensor.
- 🔐 **Sin contraseñas hardcodeadas** — todo vía variables de entorno (`.env`).

---

## 🚀 Cómo ejecutarlo EN VIVO

> La captura en vivo requiere privilegios: **`sudo`** en Linux, **administrador + [Npcap](https://npcap.com)** en Windows.

### 🐧 Linux (Ubuntu / Kali / Debian)
```bash
# Requisitos (una vez):
sudo apt update && sudo apt install -y python3-venv python3-pip git

# Arrancar el IDS EN VIVO (instala dependencias la primera vez):
bash run_live.sh

# En OTRA terminal, el dashboard:
sudo ./venv/bin/python3 -m src.web.app
```
Abre el panel en **http://127.0.0.1:5000**.

### 🪟 Windows

> ⚠️ El `ids.exe` **no viene en el repositorio** (los binarios no se versionan). Hay que **construirlo** una vez, o ejecutar desde código.

**Opción A — Construir el ejecutable y usarlo:**
1. Instala **[Npcap](https://npcap.com)** y **Python**.
2. Doble clic en **`build_exe.bat`** → genera `dist\ids.exe` (tarda unos minutos).
3. Doble clic en **`dist\ids.exe`** → acepta los permisos (UAC) → captura en vivo + panel.

> Si descargaste el `.exe` ya hecho (de la pestaña **Releases** o del `IDS-Windows.zip`), te saltas los pasos 1-2: solo instala Npcap y doble clic en `ids.exe`.

**Opción B — Desde código (sin construir el `.exe`):**
PowerShell **como administrador**, con Npcap instalado:
```powershell
python -m venv venv
venv\Scripts\python.exe -m pip install -r requirements.txt
venv\Scripts\python.exe -m src.main --auto      # IDS en vivo
venv\Scripts\python.exe -m src.web.app           # en otra ventana: dashboard
```

---

## 📋 Requisitos
- **Python 3.11+**
- **Linux** (Kali/Ubuntu recomendado) o **Windows**
- Captura en vivo: `sudo` (Linux) · **Npcap** + administrador (Windows)

## 🔐 Seguridad y credenciales
- Las credenciales (SMTP, API keys) viven **solo** en `.env` (ignorado por git). El código las lee con `os.getenv()`; **no hay nada hardcodeado**.
- Copia `.env.example` a `.env` y rellena tus datos, **o** configúralo desde el panel (vista *Correo*).

## 🧱 Modelo OSI (dónde actúa)
- **Capa 2 (Enlace):** MAC → listas blancas, detección de equipos.
- **Capa 3 (Red):** IP → listas blancas/negras, bloqueo IPS.
- **Capa 7 (Aplicación):** DNS/HTTP → monitoreo de sitios.

## 🗂️ Estructura del proyecto
```
ids/
├── launcher.py             # punto de entrada del ejecutable (.exe), en vivo
├── build_exe.bat / .sh     # construye el .exe con PyInstaller
├── run_live.sh             # corre el IDS EN VIVO (Linux)
├── run_dashboard.sh / .bat # levanta el dashboard web
├── requirements.txt
├── .env.example            # plantilla de secretos (sin valores reales)
├── config/
│   ├── settings.yaml        # interfaz, subred, email admin, umbrales
│   ├── whitelist.yaml       # IPs/MACs autorizadas (Capa 2/3)
│   └── blacklist_manual.txt # lista negra manual (complementa el feed)
├── src/
│   ├── paths.py             # rutas (compatible con .exe)
│   ├── config_loader.py     # carga de config + secretos (.env)
│   ├── capture.py           # sniffer Scapy + dispatcher
│   ├── whitelist.py         # Módulo 1: Listas Blancas
│   ├── site_monitor.py      # Módulo 2: Monitoreo de Sitios
│   ├── threat_intel.py      # Módulo 3: IPs Peligrosas
│   ├── forensics.py         # Módulo 4: Forense (Whois/AbuseIPDB)
│   ├── notifier.py          # alertas por correo (SMTP)
│   ├── reporter.py          # bitácora en SQLite
│   ├── firewall.py          # Modo IPS (bloqueo automático)
│   ├── main.py              # orquestador del IDS
│   └── web/app.py           # dashboard web (Flask)
├── tools/
│   ├── reporte.py           # ver la bitácora por consola
│   └── smoke_test.py        # verifica el entorno
└── logs/                    # bitácora (se genera sola)
```



## ⚠️ Aviso
Proyecto **educativo**. Úsalo únicamente en redes propias o con autorización explícita.
El monitoreo de redes puede estar regulado por la ley (en México, la **LFPDPPP** y artículos
constitucionales sobre privacidad).
