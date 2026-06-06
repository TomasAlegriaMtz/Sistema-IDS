# IDS — Sistema de Detección de Intrusos

Sistema de Detección de Intrusos (IDS) educativo escrito en **Python** sobre
**Scapy**. Monitorea una red en **Capa 2/3/7** del modelo OSI y notifica por
correo al administrador ante eventos de seguridad.

> Proyecto académico. Licencia **GNU GPL v3**.

## Módulos

1. **Listas Blancas (Capa 2 y 3)** — detecta MAC/IP no autorizadas y alerta.
2. **Monitoreo de Sitios** — bitácora en tiempo real de dominios (DNS/HTTP).
3. **IPs Peligrosas (Threat Intel)** — alerta ante conexiones a IPs maliciosas.
4. **Automatización Forense** — consulta Whois/abuse de la IP peligrosa.

## Requisitos

- **Kali Linux** (recomendado) u otra distro Debian/Ubuntu.
- **Python 3.11+**
- Privilegios de captura de paquetes (`sudo`).
- En Kali ya vienen preinstalados: Scapy, libpcap, whois, tcpdump.

## Instalación (Kali Linux)

```bash
# 1) Dependencias del sistema (en Kali casi todo ya viene)
sudo apt update
sudo apt install -y python3-venv python3-pip libpcap-dev whois

# 2) Entorno virtual (OBLIGATORIO en Kali por PEP 668)
python3 -m venv venv
source venv/bin/activate

# 3) Librerías del proyecto
pip install -r requirements.txt

# 4) Credenciales: copia la plantilla y rellena tus datos
cp .env.example .env
nano .env
```

## Verificar el entorno

```bash
sudo ./venv/bin/python3 tools/smoke_test.py
```

Si ves `Entorno LISTO`, todo está correcto.

## Estructura del proyecto

```
ids/
├── .env.example            # plantilla de secretos (SMTP, API keys)
├── requirements.txt        # dependencias de Python
├── config/
│   ├── settings.yaml       # subred, email admin, umbrales
│   ├── whitelist.yaml      # IPs y MACs autorizadas (Capa 2/3)
│   └── blacklist.cache     # caché del feed de IPs maliciosas
├── src/
│   ├── config_loader.py    # carga de config + secretos
│   ├── capture.py          # sniffer Scapy + dispatcher
│   ├── whitelist.py        # Módulo 1
│   ├── site_monitor.py     # Módulo 2
│   ├── threat_intel.py     # Módulo 3
│   ├── forensics.py        # Módulo 4
│   ├── notifier.py         # alertas por correo (SMTP)
│   └── reporter.py         # bitácora SQLite + vista CLI
├── tools/
│   ├── smoke_test.py       # verifica el entorno
│   └── make_demo_pcap.py   # genera el .pcap de demostración
└── logs/
    └── ids.db              # base de datos de la bitácora
```

## Ejecución (cuando esté completo)

```bash
# Captura en vivo (interfaz definida en settings.yaml)
sudo ./venv/bin/python3 -m src.main

# Modo demo (lee un .pcap pregrabado)
#   define network.pcap_file en config/settings.yaml
```
