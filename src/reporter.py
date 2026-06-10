from __future__ import annotations

import sqlite3
import threading
from datetime import datetime
from pathlib import Path

from src.paths import BASE_DIR

class Reporter:
    def __init__(self, settings: dict):
        db_rel = (settings.get("logging", {}) or {}).get("database", "logs/ids.db")
        self.db_path = BASE_DIR / db_rel
        self.db_path.parent.mkdir(parents=True, exist_ok=True)

        self._lock = threading.Lock()
        self._conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
        self._crear_tablas()

    def _crear_tablas(self):
        with self._lock:
            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS visitas (
                    id      INTEGER PRIMARY KEY AUTOINCREMENT,
                    fecha   TEXT NOT NULL,
                    src_ip  TEXT,
                    dominio TEXT,
                    tipo    TEXT
                )
                """
            )
            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS alertas (
                    id        INTEGER PRIMARY KEY AUTOINCREMENT,
                    fecha     TEXT NOT NULL,
                    severidad TEXT,
                    titulo    TEXT,
                    src_ip    TEXT,
                    detalle   TEXT
                )
                """
            )
            self._conn.commit()

    def registrar_visita(self, src_ip: str, dominio: str, tipo: str):
        fecha = datetime.now().isoformat(sep=" ", timespec="seconds")
        with self._lock:
            self._conn.execute(
                "INSERT INTO visitas (fecha, src_ip, dominio, tipo) VALUES (?, ?, ?, ?)",
                (fecha, src_ip, dominio, tipo),
            )
            self._conn.commit()

    def registrar_alerta(self, severidad: str, titulo: str, src_ip: str, detalle: str = ""):
        fecha = datetime.now().isoformat(sep=" ", timespec="seconds")
        with self._lock:
            self._conn.execute(
                "INSERT INTO alertas (fecha, severidad, titulo, src_ip, detalle) "
                "VALUES (?, ?, ?, ?, ?)",
                (fecha, severidad, titulo, src_ip, detalle),
            )
            self._conn.commit()

    def visitas_recientes(self, limite: int = 50):
        with self._lock:
            cur = self._conn.execute(
                "SELECT fecha, src_ip, dominio, tipo "
                "FROM visitas ORDER BY id DESC LIMIT ?",
                (limite,),
            )
            return cur.fetchall()

    def total_visitas(self) -> int:
        with self._lock:
            cur = self._conn.execute("SELECT COUNT(*) FROM visitas")
            return cur.fetchone()[0]
