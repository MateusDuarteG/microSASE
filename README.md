# microSASE - Secure Access Service Edge (Control Plane)

O **microSASE** é uma solução inspirada na arquitetura **SASE (Secure Access Service Edge)**, combinando rede (VPN WireGuard) e segurança (Firewall/ACL) em um plano de controle centralizado. O projeto oferece telemetria de tráfego em tempo real, gestão dinâmica de políticas de acesso e execução isolada em container Docker.

---

## 🖥️ Painel de Operações & Visão Geral (Control Plane)

O Dashboard interativo (desenvolvido em Streamlit) funciona como um centro de operações estilo **SOC (Security Operations Center)**, fornecendo visibilidade e gestão em 4 níveis:

### 1. Saúde da Infraestrutura
- **Status da API**: Monitoramento contínuo da disponibilidade do backend e do container.

### 2. Métricas Globais da Rede
- **Dispositivos Conectados**: Contagem de nós/peers WireGuard ativos na malha.
- **Tráfego Total (24h)**: Volume consolidado de dados trafegados (Download/Upload).
- **Bloqueios Ativos (ACL)**: Quantidade de regras de restrição aplicando segurança na rede em tempo real.

### 3. Telemetria e Monitoramento de Nós
- **Identificação de Dispositivos**: Mapeamento de nomes de nós e IPs atribuídos na VPN (`10.0.0.x`).
- **Consumo de Banda**: Telemetria individual de tráfego por cliente em MB.
- **Estado de Sessão**: Indicador em tempo real de peers ativos e inativos.

### 4. Gestão Operacional & Segurança
- **🔒 Regras de ACL**: Aplicação dinâmica de políticas de bloqueio/liberação de IP direto nas tabelas de firewall Linux (`iptables`).
- **👥 Gestão de Peers**: Visualização e cadastro de chaves públicas do WireGuard.

---

## 🛠️ Arquitetura & Tecnologias

- **Backend / API**: Python 3.11 + FastAPI + Uvicorn
- **Frontend / Dashboard**: Streamlit + Pandas
- **Segurança & Rede**: WireGuard tools, `iptables`, `iproute2`
- **Containerização**: Docker / Docker Compose (`NET_ADMIN` ativado para manipulação de rede Linux)

---

## 🚀 Como Executar o Projeto

### Opção 1: Via Docker (Recomendado)

Certifique-se de ter o Docker Desktop instalado e ativo:

```bash
# Sobe a API e o Dashboard isolados em container Linux
docker compose up --build -d

# Acompanhar logs do container
docker compose logs -f