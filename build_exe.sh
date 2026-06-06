#!/usr/bin/env bash
# =====================================================================
#   Construye el ejecutable del IDS (Linux) con PyInstaller.
#   Genera dist/ids listo para distribuir (binario + config + demo.pcap).
#   Nota: el binario de Linux solo sirve en Linux (no en Windows).
# =====================================================================
cd "$(dirname "$0")"

echo "[1/4] Preparando entorno de compilacion..."
python3 -m venv build-venv
build-venv/bin/python3 -m pip install --upgrade pip
build-venv/bin/python3 -m pip install -r requirements.txt pyinstaller

echo "[2/4] Generando el escenario demo.pcap..."
build-venv/bin/python3 tools/make_demo_pcap.py

echo "[3/4] Empaquetando el ejecutable (tarda unos minutos)..."
build-venv/bin/pyinstaller --onefile --name ids --noconfirm \
  --collect-all scapy --collect-all ipwhois launcher.py

echo "[4/4] Copiando config y demo junto al binario..."
cp -r config dist/config
mkdir -p dist/tools
cp tools/demo.pcap dist/tools/ 2>/dev/null || true
cp LEEME_EXE.txt dist/ 2>/dev/null || true

echo ""
echo "LISTO. Distribuye la carpeta dist/ (ids + config + tools/demo.pcap)."
