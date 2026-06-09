#!/usr/bin/env bash
# =====================================================================
#   Construye el ejecutable del IDS (Linux) con PyInstaller.
#   Captura EN VIVO. Genera dist/ids listo para distribuir (binario + config).
#   Nota: el binario de Linux solo sirve en Linux (no en Windows).
# =====================================================================
cd "$(dirname "$0")"

echo "[1/3] Preparando entorno de compilacion..."
python3 -m venv build-venv
build-venv/bin/python3 -m pip install --upgrade pip
build-venv/bin/python3 -m pip install -r requirements.txt pyinstaller

echo "[2/3] Empaquetando el ejecutable (tarda unos minutos)..."
build-venv/bin/pyinstaller --onefile --name ids --noconfirm \
  --collect-all scapy --collect-all ipwhois launcher.py

echo "[3/3] Copiando config junto al binario..."
cp -r config dist/config
cp LEEME_EXE.txt dist/ 2>/dev/null || true

echo ""
echo "LISTO. Distribuye la carpeta dist/ (ids + config). Ejecutar con sudo."
