# Imagem base oficial do Python em ambiente Linux
FROM python:3.10-slim

# Instala ferramentas de rede e WireGuard no container Linux
RUN apt-get update && apt-get install -y \
    wireguard-tools \
    iptables \
    iproute2 \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Define o diretório de trabalho dentro do container
WORKDIR /app

# Copia os arquivos de dependências
COPY requirements.txt .

# Instala as dependências Python
RUN pip install --no-cache-dir -r requirements.txt

# Copia todo o código-fonte da aplicação
COPY . .

# Expõe as portas da API (8000) e do Dashboard Streamlit (8501)
EXPOSE 8000
EXPOSE 8501

# Script de inicialização que sobe a API e o Dashboard juntos
CMD uvicorn main:app --host 0.0.0.0 --port 8000 & streamlit run dashboard.py --server.port=8501 --server.address=0.0.0.0