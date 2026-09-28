from fastapi import FastAPI, HTTPException, Depends, status
from pydantic import BaseModel
from typing import Optional, List
import database
from wireguard_core import WireGuardManager
from acl_engine import ACLEngine

# Inicializa o FastAPI e o Banco de Dados
app = FastAPI(
    title="Micro-SASE Zero Trust API",
    description="API para gerenciamento de VPN WireGuard, ACLs e Controle de Acesso Zero Trust",
    version="1.0.0"
)

# Inicializa os motores
wg_manager = WireGuardManager(
    interface="wg0",
    server_public_key="CHAVE_PUBLICA_DO_SEU_SERVIDOR_AQUI",
    server_endpoint="vpn.suaempresa.com:51820",
    dns_server="10.0.0.1"
)
acl_engine = ACLEngine(wg_interface="wg0")

@app.on_event("startup")
def startup_event():
    """Inicializa as tabelas do banco ao subir a aplicação."""
    database.init_db()

# ----------------------------------------------------------------------
# Modelos de Dados (Schemas Pydantic)
# ----------------------------------------------------------------------
class UserCreate(BaseModel):
    username: str
    email: str
    password: str

class PeerCreate(BaseModel):
    user_id: int
    device_name: str
    allocated_ip: str

class ACLCreate(BaseModel):
    peer_id: int
    destination_ip: str
    destination_port: Optional[int] = 0
    protocol: Optional[str] = "ALL"
    action: Optional[str] = "ALLOW"
    description: Optional[str] = ""

# ----------------------------------------------------------------------
# Endpoints da API
# ----------------------------------------------------------------------

@app.get("/")
def read_root():
    return {"system": "Micro-SASE Zero Trust Gateway", "status": "online"}

# 1. Cadastrar Usuário
@app.post("/users/register", status_code=status.HTTP_201_CREATED)
def register_user(user: UserCreate):
    conn = database.get_connection()
    cursor = conn.cursor()
    try:
        cursor.execute(
            "INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)",
            (user.username, user.email, user.password) # Em produção, usar hash de senha (ex: passlib)
        )
        conn.commit()
        user_id = cursor.lastrowid
        return {"id": user_id, "username": user.username, "email": user.email}
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Erro ao cadastrar usuário: {e}")
    finally:
        conn.close()

# 2. Criar Novo Peer WireGuard + Gerar Arquivo .conf
@app.post("/peers/create")
def create_peer(peer_data: PeerCreate):
    # Gera o par de chaves e a PSK
    keys = wg_manager.generate_keypair()

    # Salva no Banco de Dados
    peer_id = database.register_peer(
        user_id=peer_data.user_id,
        device_name=peer_data.device_name,
        public_key=keys["public_key"],
        preshared_key=keys["preshared_key"],
        allocated_ip=peer_data.allocated_ip
    )

    # Aplica o peer diretamente no Kernel do WireGuard sem reiniciar a interface
    wg_manager.add_peer(
        client_public_key=keys["public_key"],
        client_ip=peer_data.allocated_ip,
        preshared_key=keys["preshared_key"]
    )

    # Gera o arquivo textual de configuração (.conf)
    client_config = wg_manager.generate_client_config(
        client_private_key=keys["private_key"],
        client_ip=peer_data.allocated_ip,
        preshared_key=keys["preshared_key"]
    )

    return {
        "peer_id": peer_id,
        "device_name": peer_data.device_name,
        "allocated_ip": peer_data.allocated_ip,
        "config_file": client_config
    }

# 3. Adicionar Regra de Acesso Zero Trust (ACL)
@app.post("/acls/add")
def add_acl(acl: ACLCreate):
    database.add_acl_rule(
        peer_id=acl.peer_id,
        destination_ip=acl.destination_ip,
        destination_port=acl.destination_port,
        protocol=acl.protocol,
        action=acl.action,
        description=acl.description
    )

    # Sincroniza o Firewall (iptables) imediatamente com a nova regra
    acl_engine.sync_acls()

    return {"status": "success", "message": "Regra Zero Trust aplicada no Firewall com sucesso!"}

# 4. Kill Switch / Alternar Status do Peer
@app.post("/peers/{peer_id}/toggle")
def toggle_peer_status(peer_id: int, active: bool):
    database.set_peer_status(peer_id, active)

    conn = database.get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT public_key FROM peers WHERE id = ?", (peer_id,))
    row = cursor.fetchone()
    conn.close()

    if row:
        pub_key = row["public_key"]
        if not active:
            # Revoga no WireGuard imediatamente
            wg_manager.remove_peer(pub_key)
        
        # Recarrega regras do Firewall
        acl_engine.sync_acls()

    return {"peer_id": peer_id, "is_active": active}

# 5. Listar Métricas do Dashboard
@app.get("/dashboard/stats")
def get_dashboard_stats():
    conn = database.get_connection()
    cursor = conn.cursor()
    
    cursor.execute("SELECT COUNT(*) as total FROM users")
    total_users = cursor.fetchone()["total"]

    cursor.execute("SELECT COUNT(*) as total FROM peers WHERE is_active = 1")
    active_peers = cursor.fetchone()["total"]

    cursor.execute("""
        SELECT p.device_name, p.allocated_ip, p.last_handshake, u.username 
        FROM peers p 
        JOIN users u ON p.user_id = u.id
    """)
    peers_list = [dict(row) for row in cursor.fetchall()]
    conn.close()

    return {
        "total_users": total_users,
        "active_peers": active_peers,
        "peers": peers_list
    }