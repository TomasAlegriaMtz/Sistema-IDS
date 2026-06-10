import os
import sys
import threading
import time
import webbrowser

def _es_admin_windows():
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False

def _relanzar_como_admin_windows():
    import ctypes
    from src.paths import BASE_DIR
    params = " ".join(f'"{a}"' for a in sys.argv[1:])
    ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, params, str(BASE_DIR), 1)

def _asegurar_privilegios():
    if os.name == "nt":
        if not _es_admin_windows():
            print("[launcher] Solicitando permisos de administrador (UAC)...")
            _relanzar_como_admin_windows()
            sys.exit(0)
    elif hasattr(os, "geteuid") and os.geteuid() != 0:
        print("[launcher] AVISO: la captura en vivo necesita privilegios (sudo).")

def _run_dashboard():
    from src.web.app import app
    app.run(host="127.0.0.1", port=5000, debug=False, use_reloader=False)

def main():
    _asegurar_privilegios()

    print("=" * 60)
    print("  IDS - Captura EN VIVO. Abriendo el panel web...")
    print("=" * 60)

    threading.Thread(target=_run_dashboard, daemon=True).start()
    time.sleep(1.5)
    try:
        webbrowser.open("http://127.0.0.1:5000")
    except Exception:
        pass

    from src import main as ids_main
    try:
        ids_main.main(auto=True)
    except Exception as e:
        print(f"\n[ERROR] No se pudo capturar en vivo: {e}")
        if os.name == "nt":
            print("        Instala Npcap (https://npcap.com) y abre el .exe como administrador.")
        print("        El panel sigue activo; cierra esta ventana para salir.")
        try:
            while True:
                time.sleep(3600)
        except KeyboardInterrupt:
            pass

if __name__ == "__main__":
    main()
