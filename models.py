import os
import sqlite3
import bcrypt
from dataclasses import dataclass

DB_PATH = "cartao.db"


def _conn() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


@dataclass
class CardData:
    nome: str = ""
    telefone: str = ""
    endereco: str = ""
    foto_path: str = ""
    logo_path: str = ""


def init_db():
    """Cria tabelas e insere dados iniciais se não existirem."""
    username = os.environ.get("ADMIN_USERNAME", "admin")
    password = os.environ.get("ADMIN_PASSWORD", "changeme")

    with _conn() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS card_data (
                id INTEGER PRIMARY KEY,
                nome TEXT DEFAULT '',
                telefone TEXT DEFAULT '',
                endereco TEXT DEFAULT '',
                foto_path TEXT DEFAULT '',
                logo_path TEXT DEFAULT ''
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS admin_user (
                id INTEGER PRIMARY KEY,
                username TEXT NOT NULL,
                password_hash TEXT NOT NULL
            )
        """)

        if not conn.execute("SELECT 1 FROM card_data WHERE id=1").fetchone():
            conn.execute("INSERT INTO card_data (id) VALUES (1)")

        if not conn.execute("SELECT 1 FROM admin_user WHERE id=1").fetchone():
            hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
            conn.execute(
                "INSERT INTO admin_user (id, username, password_hash) VALUES (1, ?, ?)",
                (username, hashed),
            )
        conn.commit()


def get_card() -> CardData:
    with _conn() as conn:
        row = conn.execute("SELECT * FROM card_data WHERE id=1").fetchone()
        return CardData(
            nome=row["nome"],
            telefone=row["telefone"],
            endereco=row["endereco"],
            foto_path=row["foto_path"],
            logo_path=row["logo_path"],
        )


def save_card(nome: str, telefone: str, endereco: str, foto_path: str, logo_path: str):
    with _conn() as conn:
        if foto_path and logo_path:
            conn.execute(
                "UPDATE card_data SET nome=?, telefone=?, endereco=?, foto_path=?, logo_path=? WHERE id=1",
                (nome, telefone, endereco, foto_path, logo_path),
            )
        elif foto_path:
            conn.execute(
                "UPDATE card_data SET nome=?, telefone=?, endereco=?, foto_path=? WHERE id=1",
                (nome, telefone, endereco, foto_path),
            )
        elif logo_path:
            conn.execute(
                "UPDATE card_data SET nome=?, telefone=?, endereco=?, logo_path=? WHERE id=1",
                (nome, telefone, endereco, logo_path),
            )
        else:
            conn.execute(
                "UPDATE card_data SET nome=?, telefone=?, endereco=? WHERE id=1",
                (nome, telefone, endereco),
            )
        conn.commit()


def verify_admin(username: str, password: str) -> bool:
    with _conn() as conn:
        row = conn.execute("SELECT username, password_hash FROM admin_user WHERE id=1").fetchone()
        if not row:
            return False
        return row["username"] == username and bcrypt.checkpw(
            password.encode(), row["password_hash"].encode()
        )
