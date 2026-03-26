# Versione Python basata su Debian
FROM python:3.11-slim

# Installazione Nmap, strumenti base e dipendenze per scaricare i nuovi tool (git, wget, unzip)
RUN apt-get update && apt-get install -y \
    nmap procps wget curl git unzip bsdmainutils dnsutils \
    && rm -rf /var/lib/apt/lists/*

# Installazione testssl.sh (clona l'ultima versione dal repository ufficiale)
RUN git clone --depth 1 https://github.com/drwetter/testssl.sh.git /opt/testssl \
    && ln -s /opt/testssl/testssl.sh /usr/local/bin/testssl.sh

# Installazione Nuclei e download automatico dei template di sicurezza
RUN wget https://github.com/projectdiscovery/nuclei/releases/download/v3.2.2/nuclei_3.2.2_linux_amd64.zip \
    && unzip nuclei_3.2.2_linux_amd64.zip -d /usr/local/bin/ \
    && rm nuclei_3.2.2_linux_amd64.zip \
    && chmod +x /usr/local/bin/nuclei \
    && nuclei -update-templates

# Cartella di lavoro nel container
WORKDIR /app

# Copio il file delle librerie e le installo
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copio tutti gli script Python dentro il container
COPY *.py ./

# Questo comando tiene il container in background permettendo di entrarci dentro e 
# lanciare gli script manualmente
CMD ["tail", "-f", "/dev/null"]