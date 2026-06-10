#!/usr/bin/env bash
cd "$(dirname "$0")"

if [ ! -d venv ]; then
  echo "Primero ejecuta:  bash run_demo.sh   (instala el entorno)"
  exit 1
fi

echo "Dashboard del IDS en:  http://127.0.0.1:5000   (Ctrl+C para detener)"
./venv/bin/python3 -m src.web.app
