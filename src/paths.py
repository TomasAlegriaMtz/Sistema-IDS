"""
paths.py - Ruta base del proyecto (compatible con PyInstaller)
==============================================================
Cuando el programa corre como .exe empaquetado (PyInstaller), los archivos
(__file__) viven en una carpeta temporal, NO junto al ejecutable. Por eso
calculamos BASE_DIR de forma distinta segun el modo:

  * Empaquetado (.exe): la base es la carpeta donde esta el ejecutable,
    para que encuentre config/, logs/, tools/ y .env junto a el.
  * Codigo fuente: la base es la raiz del proyecto (carpeta padre de src/).
"""
import sys
from pathlib import Path

if getattr(sys, "frozen", False):
    BASE_DIR = Path(sys.executable).resolve().parent
else:
    BASE_DIR = Path(__file__).resolve().parent.parent
