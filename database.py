import sqlite3
from typing import List, Dict, Optional, Any

DB_NAME = "micro_sase.db"

def get_connection():
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row  # Retorna resultados como dicionários
    return conn

def init_db():
    """Inicializa as tabelas no banco de dados SQLite."""
    with open("schema.sql", "r", encoding="utf-8") as f:
        schema = f.read()
    
    conn = get_connection()
    cursor = conn.cursor()
    cursor.executescript(schema)
    conn.commit()
    conn.close()
    print("✅ Banco de dados e tabelas iniciados com sucesso.")

# --- Operações de Peers & ACLs ---

def register_peer(user_id: int, device_name: str, public_key: str, preshared_key: str, allocated_ip: str) -> int:
    """Cadastra um novo Peer WireGuard associado a um usuário."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO peers (user_id, device_name, public_key, preshared_key, allocated_ip)
        VALUES (?, ?, ?, ?, ?)
    """, (user_id, device_name, public_key, preshared_key, allocated_ip))
    peer_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return peer_id

def add_acl_rule(peer_id: int, destination_ip: str, destination_port: int = 0, protocol: str = "ALL", action: str = "ALLOW", description: str = ""):
    """Adiciona uma regra de acesso (ACL Zero Trust) para um Peer."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO acls (peer_id, destination_ip, destination_port, protocol, action, description)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (peer_id, destination_ip, destination_port, protocol.upper(), action.upper(), description))
    conn.commit()
    conn.close()

def get_peer_acls(peer_id: int) -> List[Dict[str, Any]]:
    """Busca todas as regras ativas de um determinado Peer."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM acls WHERE peer_id = ?", (peer_id,))
    rules = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return rules

def set_peer_status(peer_id: int, is_active: bool):
    """Ativa ou Desativa um Peer (Kill Switch)."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE peers SET is_active = ? WHERE id = ?", (1 if is_active else 0, peer_id))
    conn.commit()
    conn.close()

if __name__ == "__main__":
    init_db()