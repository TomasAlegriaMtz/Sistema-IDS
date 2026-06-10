import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

def check(nombre, fn):
    try:
        fn()
        print(f"  [ OK ]  {nombre}")
        return True
    except Exception as e:
        print(f"  [FALLO]  {nombre}: {e}")
        return False

def _scapy_import():
    import scapy.all

def _listar_interfaces():
    from scapy.all import get_if_list
    ifaces = get_if_list()
    if not ifaces:
        raise RuntimeError("no se detectaron interfaces de red")
    print(f"           interfaces detectadas: {', '.join(ifaces)}")

def _cargar_config():
    from src.config_loader import load_settings, load_whitelist
    load_settings()
    wl = load_whitelist()
    print(f"           equipos en lista blanca: {len(wl['equipos'])}")

def _cargar_secretos():
    from src.config_loader import load_secrets
    load_secrets()

def main():
    print("=" * 50)
    print(" Verificacion de entorno del IDS")
    print("=" * 50)

    obligatorios = True
    obligatorios &= check("Importar Scapy", _scapy_import)
    obligatorios &= check("Listar interfaces de red", _listar_interfaces)
    obligatorios &= check("Cargar configuracion (YAML)", _cargar_config)

    print("\n  (opcional, para los modulos de alerta)")
    check("Cargar credenciales (.env)", _cargar_secretos)

    print("\n" + "=" * 50)
    if obligatorios:
        print(" Entorno LISTO. Ya podemos construir los modulos. ✔")
    else:
        print(" Hay pendientes obligatorios. Revisa los [FALLO] de arriba.")
    print("=" * 50)
    sys.exit(0 if obligatorios else 1)

if __name__ == "__main__":
    main()
