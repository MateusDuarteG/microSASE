-- 1. Tabela de Usuários (Autenticação e Identidade)
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username VARCHAR(50) UNIQUE NOT NULL,
    email VARCHAR(100) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    is_active BOOLEAN DEFAULT 1,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 2. Tabela de Dispositivos/Peers (Conexões VPN do WireGuard)
CREATE TABLE IF NOT EXISTS peers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    device_name VARCHAR(50) NOT NULL,
    public_key VARCHAR(64) UNIQUE NOT NULL,
    preshared_key VARCHAR(64),
    allocated_ip VARCHAR(15) UNIQUE NOT NULL, -- Ex: 10.0.0.5
    is_active BOOLEAN DEFAULT 1,              -- Kill Switch
    last_handshake TIMESTAMP NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- 3. Tabela de Regras de Acesso - ACLs (Modelo Zero Trust)
CREATE TABLE IF NOT EXISTS acls (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    peer_id INTEGER NOT NULL,
    destination_ip VARCHAR(18) NOT NULL,      -- Ex: 192.168.1.50/32 ou 10.0.0.0/24
    destination_port INTEGER DEFAULT 0,       -- 0 para TODAS as portas
    protocol VARCHAR(10) DEFAULT 'ALL',        -- TCP, UDP, ICMP, ALL
    action VARCHAR(10) DEFAULT 'ALLOW',        -- ALLOW ou DENY
    description VARCHAR(100),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (peer_id) REFERENCES peers(id) ON DELETE CASCADE
);

-- 4. Tabela de Auditoria e Logs de Conexão
CREATE TABLE IF NOT EXISTS connection_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    peer_id INTEGER NOT NULL,
    bytes_downloaded BIGINT DEFAULT 0,
    bytes_uploaded BIGINT DEFAULT 0,
    session_start TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    session_end TIMESTAMP NULL,
    FOREIGN KEY (peer_id) REFERENCES peers(id) ON DELETE CASCADE
);