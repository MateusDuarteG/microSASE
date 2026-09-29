import streamlit as st
import requests
import pandas as pd

# Configuração da página
st.set_page_config(
    page_title="microSASE - Control Plane",
    page_icon="🛡️",
    layout="wide"
)

API_URL = "http://127.0.0.1:8000"  # Ajuste a porta se a sua API rodar em outra porta

st.title("🛡️ microSASE - Dashboard de Operações & Segurança")
st.markdown("Painel de controle em tempo real para monitoramento e gestão de acessos.")

# Sidebar com status da API
st.sidebar.header("Status do Sistema")
try:
    res = requests.get(f"{API_URL}/", timeout=2) # Ajuste a rota se necessário (ex: /)
    if res.status_code == 200:
        st.sidebar.success("API Online 🟢")
    else:
        st.sidebar.warning(f"API Instável 🟡 ({res.status_code})")
except Exception:
    st.sidebar.error("API Offline 🔴")

# Abas do Dashboard
tab1, tab2, tab3 = st.tabs(["📊 Visão Geral & Métricas", "🔒 Regras de ACL", "👥 Peers / Dispositivos"])

with tab1:
    st.subheader("Métricas de Tráfego e Conexões")
    col1, col2, col3 = st.columns(3)
    col1.metric(label="Dispositivos Conectados", value="12", delta="+2 hoje")
    col2.metric(label="Tráfego Total (24h)", value="4.2 GB", delta="12%")
    col3.metric(label="Bloqueios Ativos (ACL)", value="5", delta="-1")

    st.markdown("---")
    st.write("### Tráfego Recente por Nó")
    # Exemplo mock/visualização de tráfego
    df_traffic = pd.DataFrame({
        "Nó / Dispositivo": ["Peer-Alpha (10.0.0.2)", "Peer-Beta (10.0.0.3)", "Peer-Gamma (10.0.0.4)"],
        "Download (MB)": [450, 1200, 80],
        "Upload (MB)": [120, 340, 15],
        "Status": ["Ativo", "Ativo", "Inativo"]
    })
    st.dataframe(df_traffic, use_container_width=True)

with tab2:
    st.subheader("Gerenciamento de Regras de Acesso (ACL)")
    st.info("Altere o status de acesso em tempo real via chamadas de API. Aceita endereços IP e URLs/Domínios.")
    
    col_target, col_action, col_btn = st.columns([3, 2, 2])
    
    with col_target:
        # Alterado de "IP do Alvo" para aceitar IPs ou URLs
        target_input = st.text_input("IP ou URL/Domínio do Alvo", value="10.0.0.2", help="Exemplos: 10.0.0.2, facebook.com, site-malicioso.com")
        
    with col_action:
        action = st.selectbox("Ação", ["BLOQUEAR", "LIBERAR"])
        
    with col_btn:
        st.write("")
        st.write("")
        if st.button("Aplicar Regra"):
            # Mapeia a ação do selectbox para o padrão esperado no backend
            action_code = "BLOCK" if action == "BLOQUEAR" else "ALLOW"
            
            # Limpeza rápida de protocolo caso colado direto da barra do navegador
            target_clean = target_input.replace("https://", "").replace("http://", "").strip().split('/')[0]
            
            # Payload ajustado conforme o schema ACLCreate do main.py
            payload = {
                "peer_id": 1,
                "destination_ip": target_clean,
                "destination_port": 0,
                "protocol": "ALL",
                "action": action_code,
                "description": f"Regra aplicada via Dashboard para {target_clean}"
            }
            
            try:
                # Ajustada a rota para /acls/add correspondente ao main.py
                response = requests.post(f"{API_URL}/acls/add", json=payload, timeout=5)
                
                if response.status_code == 200:
                    st.success(f"Regra [{action}] aplicada com sucesso para '{target_clean}'!")
                else:
                    st.error(f"Erro ao aplicar registro: {response.status_code} - {response.text}")
            except Exception as e:
                st.error(f"Falha de conexão com a API: {e}")

with tab3:
    st.subheader("Dispositivos e Chaves WireGuard")
    st.write("Lista de Peers registrados na rede SASE.")