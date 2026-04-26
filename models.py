import os
import sqlite3
import bcrypt
from dataclasses import dataclass

# Em produção (Railway), configure DATA_DIR apontando para um volume persistente
_data_dir = os.environ.get("DATA_DIR", ".")
os.makedirs(_data_dir, exist_ok=True)  # cria /data se não existir
DB_PATH = os.path.join(_data_dir, "cartao.db")


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
    bg_path: str = ""


def init_db():
    username = os.environ.get("ADMIN_USERNAME", "admin")
    password = os.environ.get("ADMIN_PASSWORD", "changeme")

    with _conn() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS card_data (
                id       INTEGER PRIMARY KEY,
                nome     TEXT DEFAULT '',
                telefone TEXT DEFAULT '',
                endereco TEXT DEFAULT '',
                foto_path TEXT DEFAULT '',
                logo_path TEXT DEFAULT '',
                bg_path  TEXT DEFAULT ''
            )
        """)
        # Migração: adiciona bg_path se tabela já existia sem ela
        cols = [r[1] for r in conn.execute("PRAGMA table_info(card_data)").fetchall()]
        if "bg_path" not in cols:
            conn.execute("ALTER TABLE card_data ADD COLUMN bg_path TEXT DEFAULT ''")

        conn.execute("""
            CREATE TABLE IF NOT EXISTS admin_user (
                id            INTEGER PRIMARY KEY,
                username      TEXT NOT NULL,
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
    """Lê do banco. Campos de texto vazios fazem fallback para variáveis de ambiente."""
    with _conn() as conn:
        row = conn.execute("SELECT * FROM card_data WHERE id=1").fetchone()
        nome     = row["nome"]     or os.environ.get("CARD_NOME", "")
        telefone = row["telefone"] or os.environ.get("CARD_TELEFONE", "")
        endereco = row["endereco"] or os.environ.get("CARD_ENDERECO", "")
        return CardData(
            nome=nome,
            telefone=telefone,
            endereco=endereco,
            foto_path=row["foto_path"],
            logo_path=row["logo_path"],
            bg_path=row["bg_path"],
        )


def save_card(nome: str, telefone: str, endereco: str,
              foto_path: str, logo_path: str, bg_path: str):
    with _conn() as conn:
        # Busca valores atuais para não sobrescrever imagens com string vazia
        cur = conn.execute("SELECT foto_path, logo_path, bg_path FROM card_data WHERE id=1").fetchone()
        conn.execute(
            """UPDATE card_data
               SET nome=?, telefone=?, endereco=?,
                   foto_path=?, logo_path=?, bg_path=?
               WHERE id=1""",
            (
                nome, telefone, endereco,
                foto_path  or cur["foto_path"],
                logo_path  or cur["logo_path"],
                bg_path    or cur["bg_path"],
            ),
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
