# Versione Python basata su Debian
FROM python:3.11-slim

# Installazione Nmap e strumenti di rete base
RUN apt-get update && apt-get install -y nmap procps && rm -rf /var/lib/apt/lists/*

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