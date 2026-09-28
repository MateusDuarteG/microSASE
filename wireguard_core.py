import subprocess
import platform
import secrets
import base64
from pathlib import Path
from typing import Dict, Optional

IS_WINDOWS = platform.system() == "Windows"

class WireGuardManager:
    def __init__(
        self,
        interface: str = "wg0",
        server_public_key: str = "CHAVE_PUBLICA_TESTE",
        server_endpoint: str = "203.0.113.1:51820",
        dns_server: str = "10.0.0.1",
        network_cidr: str = "10.0.0.0/24"
    ):
        self.interface = interface
        self.server_public_key = server_public_key
        self.server_endpoint = server_endpoint
        self.dns_server = dns_server
        self.network_cidr = network_cidr

    @staticmethod
    def generate_keypair() -> Dict[str, str]:
        """Gera chaves reais no Linux ou chaves simuladas no Windows."""
        if IS_WINDOWS:
            # No Windows, gera strings base64 sintaticamente válidas para testes
            return {
                "private_key": base64.b64encode(secrets.token_bytes(32)).decode('utf-8'),
                "public_key": base64.b64encode(secrets.token_bytes(32)).decode('utf-8'),
                "preshared_key": base64.b64encode(secrets.token_bytes(32)).decode('utf-8')
            }

        try:
            private_key = subprocess.check_output(["wg", "genkey"], text=True).strip()
            public_key = subprocess.check_output(["wg", "pubkey"], input=private_key, text=True).strip()
            preshared_key = subprocess.check_output(["wg", "genpsk"], text=True).strip()
            return {
                "private_key": private_key,
                "public_key": public_key,
                "preshared_key": preshared_key
            }
        except Exception as e:
            raise RuntimeError(f"Erro ao gerar chaves WireGuard: {e}")

    def generate_client_config(
        self,
        client_private_key: str,
        client_ip: str,
        preshared_key: Optional[str] = None,
        allowed_ips: str = "0.0.0.0/0, ::/0"
    ) -> str:
        config = [
            "[Interface]",
            f"PrivateKey = {client_private_key}",
            f"Address = {client_ip}/32",
            f"DNS = {self.dns_server}",
            "",
            "[Peer]",
            f"PublicKey = {self.server_public_key}",
            f"Endpoint = {self.server_endpoint}",
            f"AllowedIPs = {allowed_ips}",
            "PersistentKeepalive = 25"
        ]
        if preshared_key:
            config.insert(-2, f"PresharedKey = {preshared_key}")

        return "\n".join(config)

    def add_peer(self, client_public_key: str, client_ip: str, preshared_key: Optional[str] = None) -> bool:
        if IS_WINDOWS:
            print(f"⚡ [SIMULAÇÃO WINDOWS] Peer adicionado: {client_public_key[:8]}... (IP: {client_ip})")
            return True

        command = ["wg", "set", self.interface, "peer", client_public_key, "allowed-ips", f"{client_ip}/32"]
        try:
            subprocess.run(command, check=True)
            return True
        except Exception as e:
            print(f"Erro ao adicionar peer: {e}")
            return False

    def remove_peer(self, client_public_key: str) -> bool:
        if IS_WINDOWS:
            print(f"⚡ [SIMULAÇÃO WINDOWS] Peer removido: {client_public_key[:8]}...")
            return True

        command = ["wg", "set", self.interface, "peer", client_public_key, "remove"]
        try:
            subprocess.run(command, check=True)
            return True
        except Exception as e:
            print(f"Erro ao remover peer: {e}")
            return False