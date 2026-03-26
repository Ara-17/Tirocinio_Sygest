# Progetto Sygest - Security & Vulnerability Monitoring

Sistema automatizzato per il monitoraggio continuo della sicurezza dei server aziendali. 
Il progetto sfrutta un'architettura a microservizi (Docker) per raccogliere passivamente report di vulnerabilità (modello Push tramite Aqua Trivy), analizzare la validità dei certificati SSL/HTTP Headers (modello Pull), e orchestrare gli allarmi tramite Zabbix con apertura e aggiornamento dinamico delle Issue su GitLab.

## Funzionalità Principali

* **Scansione File System (Push):** Un'API REST in Flask riceve i report generati dagli agenti Aqua Trivy direttamente dai server Windows tramite script PowerShell multi-disco.
* **Scansione Web & SSL (Pull):** Script Python orchestrano `testssl.sh` e `nuclei` per valutare i certificati e gli HTTP Security Headers, applicando regole di linting personalizzate.
* **Zabbix Orchestrator:** Zabbix riceve i dati tramite Trapper Items, calcola i gradi di sicurezza (da A+ a F) e lancia i trigger tramite una logica a impulsi per evitare spam di notifiche.
* **GitLab Smart Webhook:** Un webhook JavaScript personalizzato gestisce il ciclo di vita delle Issue su GitLab: le crea, le aggiorna in caso di peggioramenti, inserisce report in Markdown con sezioni collassabili e applica etichette dinamiche (es. `headers-grade::A+`).

## Requisiti Preliminari

* **Docker** e **Docker Compose** installati sul server host.
* Accesso a un server GitLab (SaaS o Self-Hosted) con un Personal Access Token autorizzato a gestire le Issue.

## Installazione e Setup

**1. Clonare il repository**
Scarica i file del progetto sul server Linux di destinazione.

**2. Configurare le variabili d'ambiente**
Per motivi di sicurezza, credenziali e token non sono versionati. Crea un file `.env` nella root del progetto e compilalo con i parametri di configurazione:

```env
# Database MariaDB
DB_HOST=sygest-db
DB_USER=root
DB_PASSWORD=inserire_password
DB_NAME=progetto_sygest

# Connessione Zabbix
ZABBIX_URL=http://zabbix-frontend:8080
ZABBIX_USER=Admin
ZABBIX_PASSWORD=inserire_password
ZABBIX_SERVER=zabbix-server
ZABBIX_PORT=10051

# Sicurezza API Sygest
SYGEST_API_KEY=inserire_api_key

# Integrazione GitLab
GITLAB_URL=[https://gitlab.com](https://gitlab.com)
GITLAB_TOKEN=inserire_token
GITLAB_PROJECT_ID=inserire_id_progetto
```

**3. Build e Avvio dei Container**
Al primo avvio è necessario forzare la build per permettere al container di scaricare e installare i tool di sicurezza esterni (`testssl.sh` e `nuclei`):

```bash
docker compose up -d --build
```

## Guida all'Uso e Comandi Utili

Gli script operativi risiedono nel container principale. Vanno lanciati dall'host tramite `docker exec`.

**Avviare l'API Flask in Background (Gunicorn)**
Mette in ascolto l'API per ricevere i JSON da Trivy (sostituire `nome_file_api` con il file Python corrispondente):
```bash
docker exec -d sygest-script-runner gunicorn -w 4 -b 0.0.0.0:5000 nome_file_api:app
```

**Sincronizzare Zabbix e GitLab**
Crea dinamicamente Host, Item, Trigger e Webhook su Zabbix interfacciandosi col database:
```bash
docker exec -it sygest-script-runner python zabbix_sync.py
```

**Lanciare la Scansione Web/SSL**
Forza il controllo manuale dei target web. Invia i payload a Zabbix per l'aggiornamento delle Issue su GitLab:
```bash
docker exec -it sygest-script-runner python zabbix_ssl_headers.py
```

**Pulizia Massiva GitLab (Utility)**
Script per svuotare la Issue Board di GitLab e resettare l'ambiente:
```bash
docker exec -it sygest-script-runner python clean_gitlab.py
```

## Agent Windows (Aqua Trivy)

Per i target Windows è previsto uno script PowerShell di automazione (`script_report.ps1`). 
Lo script esegue il discovery dei dischi locali, avvia la scansione Trivy su ognuno, compatta i risultati in un singolo payload JSON e lo trasmette all'API Flask autenticandosi con l'header `X-API-Key`.