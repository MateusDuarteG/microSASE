import time
import subprocess
import logging
from datetime import datetime
from database import get_connection

logging.basicConfig(level=logging.INFO, format="%(asctime)s - [MONITOR] - %(message)s")

class TrafficMonitor:
    def __init__(self, interface: str = "wg0", check_interval: int = 10, handshake_timeout: int = 180):
        self.interface = interface
        self.check_interval = check_interval       # Intervalo de checagem em segundos
        self.handshake_timeout = handshake_timeout # Se o handshake for > 180s (3 min), o peer é considerado Offline

    def get_wireguard_dump(self) -> list:
        """
        Executa 'wg show <interface> dump' e parseriza a saída.
        O formato retornado por linha é:
        public_key, preshared_key, endpoint, allowed_ips, latest_handshake, transfer_rx, transfer_tx, persistent_keepalive
        """
        try:
            output = subprocess.check_output(
                ["wg", "show", self.interface, "dump"], text=True
            ).strip()
            
            lines = output.split("\n")
            peers_data = []

            # A primeira linha é a própria interface; pulamos e pegamos apenas os peers
            for line in lines[1:]:
                parts = line.split("\t")
                if len(parts) >= 8:
                    peers_data.append({
                        "public_key": parts[0],
                        "endpoint": parts[2],
                        "allowed_ips": parts[3],
                        "latest_handshake": int(parts[4]), # Timestamp Unix
                        "bytes_received": int(parts[5]),   # Download (relativo ao servidor)
                        "bytes_sent": int(parts[6])        # Upload (relativo ao servidor)
                    })
            return peers_data
        except subprocess.CalledProcessError as e:
            logging.error(f"Erro ao executar 'wg show dump': {e}")
            return []
        except FileNotFoundError:
            logging.error("Comando 'wg' não encontrado no sistema.")
            return []

    def sync_telemetry(self):
        """Lê os dados da interface e persiste as estatísticas no banco de dados."""
        peers_telemetry = self.get_wireguard_dump()
        if not peers_telemetry:
            return

        conn = get_connection()
        cursor = conn.cursor()

        now_timestamp = int(time.time())

        for peer in peers_telemetry:
            pub_key = peer["public_key"]
            handshake = peer["latest_handshake"]
            rx = peer["bytes_received"]
            tx = peer["bytes_sent"]

            # Converte o timestamp Unix do handshake para data formatada (ou None se nunca conectou)
            last_handshake_dt = (
                datetime.fromtimestamp(handshake).strftime("%Y-%m-%d %H:%M:%S")
                if handshake > 0 else None
            )

            # 1. Atualiza o último handshake no registro do peer
            cursor.execute("""
                UPDATE peers 
                SET last_handshake = ? 
                WHERE public_key = ?
            """, (last_handshake_dt, pub_key))

            # 2. Busca o ID do peer para vincular na tabela de logs
            cursor.execute("SELECT id FROM peers WHERE public_key = ?", (pub_key,))
            row = cursor.fetchone()

            if row:
                peer_id = row["id"]
                # Grava/Atualiza o volume de tráfego consumido
                cursor.execute("""
                    INSERT INTO connection_logs (peer_id, bytes_downloaded, bytes_uploaded, session_start)
                    VALUES (?, ?, ?, CURRENT_TIMESTAMP)
                """, (peer_id, rx, tx))

                # Determina status visual de conectividade
                is_online = (handshake > 0) and ((now_timestamp - handshake) <= self.handshake_timeout)
                status_str = "🟢 ONLINE" if is_online else "🔴 OFFLINE"
                
                logging.info(
                    f"Peer ID {peer_id} [{pub_key[:8]}...] | Status: {status_str} | "
                    f"Down: {rx / (1024**2):.2f} MB | Up: {tx / (1024**2):.2f} MB"
                )

        conn.commit()
        conn.close()

    def start_monitoring(self):
        """Loop contínuo de monitoramento em segundo plano."""
        logging.info(f"🚀 Iniciando serviço de monitoramento de tráfego na interface '{self.interface}'...")
        try:
            while True:
                self.sync_telemetry()
                time.sleep(self.check_interval)
        except KeyboardInterrupt:
            logging.info("Serviço de monitoramento interrompido manualmente.")

# ----------------------------------------------------------------------
# Execução Direta
# ----------------------------------------------------------------------
if __name__ == "__main__":
    monitor = TrafficMonitor(interface="wg0", check_interval=10)
    monitor.start_monitoring()