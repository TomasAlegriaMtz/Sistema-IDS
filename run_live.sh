#!/usr/bin/env bash
# =====================================================================
#   IDS - Captura EN VIVO desde codigo (Linux: Ubuntu / Kali / Debian)
#   Crea el entorno la primera vez y arranca el IDS en vivo con la
#   interfaz y la subred AUTODETECTADAS. Requiere privilegios (sudo).
#
#   Uso:   bash run_live.sh
#   Panel: en otra terminal -> sudo ./venv/bin/python3 -m src.web.app
# =====================================================================
cd "$(dirname "$0")"

if ! command -v python3 >/dev/null 2>&1; then
  echo "ERROR: Python 3 no esta instalado.  sudo apt install -y python3-venv python3-pip"
  exit 1
fi

# Primera vez: crear entorno virtual e instalar dependencias (sin sudo)
if [ ! -d venv ]; then
  echo "[setup] Primera vez: creando entorno e instalando dependencias..."
  python3 -m venv venv || {
    echo "No se pudo crear el venv.  ->  sudo apt install -y python3-venv"
    exit 1
  }
  ./venv/bin/python3 -m pip install --upgrade pip >/dev/null
  ./venv/bin/python3 -m pip install -r requirements.txt
fi

echo "[run] Captura EN VIVO (interfaz y subred autodetectadas)..."
echo "      Para el panel web, en OTRA terminal:  sudo ./venv/bin/python3 -m src.web.app"
echo ""
sudo ./venv/bin/python3 -m src.main --auto
