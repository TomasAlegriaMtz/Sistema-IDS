"""
notifier.py - Envio de alertas por correo (SMTP)
================================================
Envia las alertas del IDS al administrador mediante SMTP (Mailtrap en pruebas).

Diseno:
  * La config de correo (servidor, usuario, password, destinatario, remitente)
    se lee FRESCA en cada envio, asi los cambios hechos desde el dashboard web
    aplican EN CALIENTE, sin reiniciar el IDS.
  * Las credenciales viven en .env (NUNCA en el codigo).
  * Si no hay SMTP valido, entra en "MODO CONSOLA": imprime las alertas en
    pantalla en vez de enviarlas (util para probar sin configurar correo).
  * El envio corre en un HILO TRABAJADOR para no bloquear la captura, con
    espaciado entre correos y reintentos (limites de planes gratuitos).
"""
from __future__ import annotations

import queue
import smtplib
import threading
import time
from email.message import EmailMessage

from src.config_loader import load_secrets


class Notificador:
    def __init__(self, settings: dict):
        self.settings = settings
        self.delay = (settings.get("alerts", {}) or {}).get("smtp_delay_seconds", 2)

        cfg = self._config()
        if cfg["ok"]:
            print(f"[notificador] SMTP listo ({cfg['host']}:{cfg['port']}) -> {cfg['to']}")
        else:
            print("[notificador] Sin SMTP valido -> MODO CONSOLA (alertas en pantalla).")

        self._cola: "queue.Queue" = queue.Queue()
        self._worker = threading.Thread(target=self._bucle, daemon=True)
        self._worker.start()

    def _config(self) -> dict:
        """Lee la configuracion de correo FRESCA (permite cambios en caliente)."""
        cfg = {"ok": False, "host": "", "port": 587, "user": "", "password": ""}
        to_env = from_env = ""
        try:
            s = load_secrets()
            cfg["host"] = s["SMTP_HOST"]
            cfg["port"] = int(s["SMTP_PORT"])
            cfg["user"] = s["SMTP_USER"]
            cfg["password"] = s["SMTP_PASSWORD"]
            cfg["ok"] = (all([cfg["host"], cfg["user"], cfg["password"]])
                         and cfg["user"] != "cambia_esto"
                         and cfg["password"] != "cambia_esto")
            to_env, from_env = s.get("ALERT_TO", ""), s.get("ALERT_FROM", "")
        except Exception:
            pass
        alerts = self.settings.get("alerts", {}) or {}
        admin = self.settings.get("admin", {}) or {}
        cfg["to"] = (to_env or "").strip() or admin.get("email", "admin@local")
        cfg["from"] = (from_env or "").strip() or alerts.get("from_address", "ids@local")
        return cfg

    def enviar(self, asunto: str, cuerpo: str):
        """Encola una alerta (no bloquea a quien la llama)."""
        self._cola.put((asunto, cuerpo))

    def esperar(self):
        """Bloquea hasta que se vacie la cola de envios (util en modo demo)."""
        self._cola.join()

    # -------------------- interno --------------------
    def _bucle(self):
        while True:
            asunto, cuerpo = self._cola.get()
            try:
                cfg = self._config()
                if cfg["ok"]:
                    self._enviar_con_reintento(cfg, asunto, cuerpo)
                else:
                    self._mostrar_consola(asunto, cuerpo)
            finally:
                self._cola.task_done()
            # Espaciar envios (los planes gratuitos limitan correos por segundo)
            time.sleep(self.delay)

    def _enviar_con_reintento(self, cfg, asunto, cuerpo, intentos=3):
        for i in range(intentos):
            try:
                self._enviar_smtp(cfg, asunto, cuerpo)
                return
            except Exception as e:
                print(f"[notificador] Error (intento {i + 1}/{intentos}): {e}")
                time.sleep(3 * (i + 1))
        print(f"[notificador] No se pudo enviar tras {intentos} intentos: {asunto}")

    def _mostrar_consola(self, asunto: str, cuerpo: str):
        print("\n" + "=" * 64)
        print(f"  ALERTA (modo consola)  ->  {asunto}")
        print("-" * 64)
        print(cuerpo)
        print("=" * 64 + "\n")

    def _enviar_smtp(self, cfg, asunto: str, cuerpo: str):
        msg = EmailMessage()
        msg["Subject"] = asunto
        msg["From"] = cfg["from"]
        msg["To"] = cfg["to"]
        msg.set_content(cuerpo)
        with smtplib.SMTP(cfg["host"], cfg["port"], timeout=20) as smtp:
            smtp.starttls()
            smtp.login(cfg["user"], cfg["password"])
            smtp.send_message(msg)
        print(f"[notificador] Correo enviado a {cfg['to']}: {asunto}")


def enviar_prueba(settings) -> tuple:
    """Envia un correo de PRUEBA con la config actual. Devuelve (ok, mensaje)."""
    from src.config_loader import load_secrets
    try:
        s = load_secrets()
        host, port = s["SMTP_HOST"], int(s["SMTP_PORT"])
        user, pwd = s["SMTP_USER"], s["SMTP_PASSWORD"]
        if not all([host, user, pwd]) or user == "cambia_esto" or pwd == "cambia_esto":
            return False, "Falta configurar el SMTP (host / usuario / contrasena)."
        alerts = settings.get("alerts", {}) or {}
        admin = settings.get("admin", {}) or {}
        to = (s.get("ALERT_TO") or "").strip() or admin.get("email", "admin@local")
        frm = (s.get("ALERT_FROM") or "").strip() or alerts.get("from_address", "ids@local")
    except Exception as e:
        return False, f"No hay SMTP valido: {e}"
    try:
        msg = EmailMessage()
        msg["Subject"] = "[IDS] Correo de prueba"
        msg["From"] = frm
        msg["To"] = to
        msg.set_content("Correo de PRUEBA del IDS. Si lo recibes, el SMTP funciona correctamente.")
        with smtplib.SMTP(host, port, timeout=20) as smtp:
            smtp.starttls()
            smtp.login(user, pwd)
            smtp.send_message(msg)
        return True, f"Correo de prueba enviado a {to}."
    except Exception as e:
        return False, f"Error al enviar: {e}"
