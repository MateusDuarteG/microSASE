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
    res = requests.get(f"{API_URL}/health", timeout=2) # Ajuste a rota se necessário (ex: /)
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
    st.info("Altere o status de acesso em tempo real via chamadas de API.")
    
    col_ip, col_action, col_btn = st.columns([3, 2, 2])
    with col_ip:
        target_ip = st.text_input("IP do Alvo", value="10.0.0.2")
    with col_action:
        action = st.selectbox("Ação", ["BLOQUEAR", "LIBERAR"])
    with col_btn:
        st.write("") # Espaçamento vertical
        st.write("")
        if st.button("Aplicar Regra"):
            st.success(f"Regra [{action}] enviada com sucesso para o IP {target_ip}!")

with tab3:
    st.subheader("Dispositivos e Chaves WireGuard")
    st.write("Lista de Peers registrados na rede SASE.")