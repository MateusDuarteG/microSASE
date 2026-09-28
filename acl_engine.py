import subprocess
import logging
import platform
from typing import List, Dict, Any
from database import get_connection

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

CHAIN_NAME = "SASE-FORWARD"
IS_WINDOWS = platform.system() == "Windows"

class ACLEngine:
    def __init__(self, wg_interface: str = "wg0"):
        self.wg_interface = wg_interface
        self._setup_chain()

    def _run_cmd(self, command: List[str]) -> subprocess.CompletedProcess:
        """Executa comandos do sistema ou simula se estiver no Windows."""
        if IS_WINDOWS:
            logging.info(f"⚡ [SIMULAÇÃO WINDOWS] Executaria comando: {' '.join(command)}")
            return subprocess.CompletedProcess(args=command, returncode=0, stdout="", stderr="")

        try:
            return subprocess.run(command, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        except subprocess.CalledProcessError as e:
            logging.error(f"Erro ao executar comando [{' '.join(command)}]: {e.stderr.strip()}")
            raise e

    def _setup_chain(self):
        """Cria a chain SASE-FORWARD no iptables se ela ainda não existir."""
        if IS_WINDOWS:
            logging.info(f"⚡ [SIMULAÇÃO WINDOWS] Configurando Chain '{CHAIN_NAME}' no Firewall...")
            return

        try:
            subprocess.run(["iptables", "-C", "FORWARD", "-i", self.wg_interface, "-j", CHAIN_NAME], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        except subprocess.CalledProcessError:
            logging.info(f"Criando e vinculando a chain de segurança '{CHAIN_NAME}' no iptables...")
            subprocess.run(["iptables", "-N", CHAIN_NAME], stderr=subprocess.DEVNULL)
            self._run_cmd(["iptables", "-I", "FORWARD", "1", "-i", self.wg_interface, "-j", CHAIN_NAME])

    def flush_sase_rules(self):
        logging.info(f"Limpando regras anteriores da chain {CHAIN_NAME}...")
        self._run_cmd(["iptables", "-F", CHAIN_NAME])

    def sync_acls(self):
        self.flush_sase_rules()
        conn = get_connection()
        cursor = conn.cursor()

        query = """
            SELECT 
                p.allocated_ip,
                a.destination_ip,
                a.destination_port,
                a.protocol,
                a.action
            FROM acls a
            JOIN peers p ON a.peer_id = p.id
            WHERE p.is_active = 1
        """
        cursor.execute(query)
        rules = [dict(row) for row in cursor.fetchall()]
        conn.close()

        for rule in rules:
            self._apply_rule_to_iptables(rule)

        self._run_cmd(["iptables", "-A", CHAIN_NAME, "-i", self.wg_interface, "-j", "DROP"])
        logging.info("✅ Sincronização de ACLs/Firewall concluída (Default DROP).")

    def _apply_rule_to_iptables(self, rule: Dict[str, Any]):
        source_ip = f"{rule['allocated_ip']}/32"
        dest_ip = rule['destination_ip']
        protocol = rule['protocol'].lower()
        port = rule['destination_port']
        target = "ACCEPT" if rule['action'].upper() == "ALLOW" else "DROP"

        cmd = ["iptables", "-A", CHAIN_NAME, "-s", source_ip, "-d", dest_ip]

        if protocol in ["tcp", "udp"] and port > 0:
            cmd.extend(["-p", protocol, "--dport", str(port)])
        elif protocol in ["tcp", "udp", "icmp"]:
            cmd.extend(["-p", protocol])

        cmd.extend(["-j", target])
        self._run_cmd(cmd)