"""
launcher.py - Punto de entrada del EJECUTABLE (.exe) del IDS  [CAPTURA EN VIVO]
==============================================================================
Doble clic:
  1. Pide permisos de administrador (UAC) automaticamente -> necesarios para
     capturar paquetes en vivo.
  2. Levanta el dashboard web y abre el navegador.
  3. Captura EN VIVO la red (interfaz y subred autodetectadas).
  4. Si no se puede capturar (falta Npcap), muestra la DEMO como respaldo.

REQUISITOS de la captura en vivo:
  * Windows: tener Npcap instalado (https://npcap.com).
  * Linux:   ejecutar con sudo.
"""
import os
import sys
import threading
import time
import webbrowser

from src.paths import BASE_DIR


def _es_admin_windows():
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def _relanzar_como_admin_windows():
    import ctypes
    params = " ".join(f'"{a}"' for a in sys.argv[1:])
    # Re-lanza el .exe pidiendo privilegios (UAC), en la carpeta del ejecutable.
    ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, params, str(BASE_DIR), 1)


def _asegurar_privilegios():
    if os.name == "nt":
        if not _es_admin_windows():
            print("[launcher] Solicitando permisos de administrador (UAC)...")
            _relanzar_como_admin_windows()
            sys.exit(0)        # esta instancia termina; sigue la elevada
    elif hasattr(os, "geteuid") and os.geteuid() != 0:
        print("[launcher] AVISO: la captura en vivo necesita privilegios.")
        print("           Si no captura, ejecuta con:  sudo ./ids")


def _run_dashboard():
    from src.web.app import app
    app.run(host="127.0.0.1", port=5000, debug=False, use_reloader=False)


def main():
    _asegurar_privilegios()

    print("=" * 60)
    print("  IDS - Captura EN VIVO. Abriendo el panel web...")
    print("=" * 60)

    # Dashboard en segundo plano + abrir navegador
    threading.Thread(target=_run_dashboard, daemon=True).start()
    time.sleep(1.5)
    try:
        webbrowser.open("http://127.0.0.1:5000")
    except Exception:
        pass

    from src import main as ids_main
    pcap = BASE_DIR / "tools" / "demo.pcap"
    try:
        # CAPTURA EN VIVO (interfaz + subred autodetectadas). Bloquea hasta Ctrl+C.
        ids_main.main(auto=True)
    except Exception as e:
        print(f"\n[aviso] No se pudo capturar en vivo: {e}")
        if os.name == "nt":
            print("        Instala Npcap (https://npcap.com) y abre el .exe como administrador.")
        if pcap.exists():
            print("[launcher] Mostrando la DEMO como respaldo...")
            try:
                ids_main.main(pcap=str(pcap))
            except Exception:
                pass

    print("\n" + "=" * 60)
    print("  Panel activo en:  http://127.0.0.1:5000")
    print("  Cierra esta ventana para salir.")
    print("=" * 60)
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
