"""
reporte.py - Muestra la bitacora de sitios visitados
=====================================================
Lee la base de datos del IDS (logs/ids.db) y muestra las ultimas visitas
registradas por el Modulo 2.

Uso:
    sudo ./venv/bin/python3 tools/reporte.py
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.config_loader import load_settings
from src.reporter import Reporter


def main():
    settings = load_settings()
    rep = Reporter(settings)
    filas = rep.visitas_recientes(50)

    print()
    print("=" * 70)
    print(f"  BITACORA DE SITIOS VISITADOS   (total historico: {rep.total_visitas()})")
    print("=" * 70)
    print(f"  {'FECHA':<20} {'ORIGEN':<16} {'TIPO':<5} DOMINIO")
    print("  " + "-" * 66)
    if not filas:
        print("  (sin registros todavia; corre el IDS y genera trafico)")
    for fecha, src_ip, dominio, tipo in filas:
        print(f"  {fecha:<20} {src_ip:<16} {tipo:<5} {dominio}")
    print("=" * 70 + "\n")


if __name__ == "__main__":
    main()
