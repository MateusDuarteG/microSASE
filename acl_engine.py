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
        """Executa comandos do sistema com tolerância a falhas para evitar Erro 500 na API."""
        if IS_WINDOWS:
            logging.info(f"⚡ [SIMULAÇÃO WINDOWS] Executaria comando: {' '.join(command)}")
            return subprocess.CompletedProcess(args=command, returncode=0, stdout="", stderr="")

        try:
            return subprocess.run(command, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        except subprocess.CalledProcessError as e:
            logging.error(f"Erro ao executar comando [{' '.join(command)}]: {e.stderr.strip()}")
            return subprocess.CompletedProcess(args=command, returncode=e.returncode, stdout="", stderr=e.stderr)
        except FileNotFoundError:
            logging.error(f"Comando '{command[0]}' não encontrado no sistema. Verifique a instalação do iptables no container.")
            return subprocess.CompletedProcess(args=command, returncode=127, stdout="", stderr="Comando não encontrado")

    def _setup_chain(self):
        """Cria e vincula a chain SASE-FORWARD no iptables (FORWARD e OUTPUT)."""
        if IS_WINDOWS:
            logging.info(f"⚡ [SIMULAÇÃO WINDOWS] Configurando Chain '{CHAIN_NAME}' no Firewall...")
            return

        # 1. Garante criação da chain personalizada
        subprocess.run(["iptables", "-N", CHAIN_NAME], stderr=subprocess.DEVNULL)

        # 2. Vincula à tabela FORWARD (tráfego encaminhado da VPN WireGuard)
        try:
            subprocess.run(["iptables", "-C", "FORWARD", "-j", CHAIN_NAME], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        except subprocess.CalledProcessError:
            logging.info(f"Vinculando a chain de segurança '{CHAIN_NAME}' na tabela FORWARD...")
            self._run_cmd(["iptables", "-I", "FORWARD", "1", "-j", CHAIN_NAME])

        # 3. Vincula à tabela OUTPUT (tráfego de saída local do container/testes)
        try:
            subprocess.run(["iptables", "-C", "OUTPUT", "-j", CHAIN_NAME], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        except subprocess.CalledProcessError:
            logging.info(f"Vinculando a chain de segurança '{CHAIN_NAME}' na tabela OUTPUT...")
            self._run_cmd(["iptables", "-I", "OUTPUT", "1", "-j", CHAIN_NAME])

    def flush_sase_rules(self):
        logging.info(f"Limpando regras anteriores da chain {CHAIN_NAME}...")
        self._run_cmd(["iptables", "-F", CHAIN_NAME])

    def sync_acls(self):
        self.flush_sase_rules()
        conn = get_connection()
        cursor = conn.cursor()

        # Busca regras associando com os peers se existirem
        query = """
            SELECT 
                p.allocated_ip,
                a.destination_ip,
                a.destination_port,
                a.protocol,
                a.action
            FROM acls a
            LEFT JOIN peers p ON a.peer_id = p.id
        """
        cursor.execute(query)
        rules = [dict(row) for row in cursor.fetchall()]
        conn.close()

        for rule in rules:
            self._apply_rule_to_iptables(rule)

        logging.info("✅ Sincronização de ACLs/Firewall concluída.")

    def _apply_rule_to_iptables(self, rule: Dict[str, Any]):
        dest_ip = rule.get('destination_ip')
        
        # Ignora registros nulos ou textos genéricos de placeholder
        if not dest_ip or dest_ip.strip().lower() == "string":
            logging.warning(f"⚠️ Regra ignorada por destino inválido: '{dest_ip}'")
            return

        source_ip = rule.get('allocated_ip')
        protocol = str(rule.get('protocol', 'all')).lower()
        port = rule.get('destination_port', 0)
        action = str(rule.get('action', '')).upper()
        target = "ACCEPT" if action in ["ALLOW", "LIBERAR"] else "DROP"

        cmd = ["iptables", "-A", CHAIN_NAME]
        
        # Define IP de origem apenas se houver um peer específico vinculado
        if source_ip and source_ip not in ['0.0.0.0/0', '0.0.0.0']:
            if not source_ip.endswith('/32') and '/' not in source_ip:
                source_ip = f"{source_ip}/32"
            cmd.extend(["-s", source_ip])

        cmd.extend(["-d", dest_ip])

        # Define protocolo e porta
        if protocol in ["tcp", "udp"] and port > 0:
            cmd.extend(["-p", protocol, "--dport", str(port)])
        elif protocol in ["tcp", "udp", "icmp"]:
            cmd.extend(["-p", protocol])

        cmd.extend(["-j", target])
        self._run_cmd(cmd)