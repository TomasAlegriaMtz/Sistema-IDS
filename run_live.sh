#!/usr/bin/env bash
cd "$(dirname "$0")"

if ! command -v python3 >/dev/null 2>&1; then
  echo "ERROR: Python 3 no esta instalado.  sudo apt install -y python3-venv python3-pip"
  exit 1
fi

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
