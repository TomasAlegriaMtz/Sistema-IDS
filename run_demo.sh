#!/usr/bin/env bash
# =====================================================================
#  IDS - Lanzador de la DEMO para Linux / macOS
#  Crea el entorno la primera vez, genera el escenario y ejecuta el IDS.
#  La demo (.pcap) NO requiere root ni Npcap/libpcap.
#  Uso:   bash run_demo.sh
# =====================================================================
cd "$(dirname "$0")"

if ! command -v python3 >/dev/null 2>&1; then
  echo "ERROR: Python 3 no esta instalado. Instalalo y reintenta."
  exit 1
fi

# Primera vez: crear entorno virtual e instalar dependencias
if [ ! -d venv ]; then
  echo "[setup] Primera vez: creando entorno e instalando dependencias..."
  python3 -m venv venv || {
    echo "No se pudo crear el venv. En Debian/Ubuntu/Kali:  sudo apt install -y python3-venv"
    exit 1
  }
  ./venv/bin/python3 -m pip install --upgrade pip >/dev/null
  ./venv/bin/python3 -m pip install -r requirements.txt
fi

# Generar el escenario de demostracion si no existe
if [ ! -f tools/demo.pcap ]; then
  echo "[setup] Generando escenario de demostracion (demo.pcap)..."
  ./venv/bin/python3 tools/make_demo_pcap.py
fi

echo "[run] Iniciando IDS en modo DEMO..."
echo "      (para ver el panel web, ejecuta en otra terminal: bash run_dashboard.sh)"
echo ""
./venv/bin/python3 -m src.main --pcap tools/demo.pcap
