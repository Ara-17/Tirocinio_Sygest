# Progetto Sygest - Security & Vulnerability Monitoring

Sistema automatizzato per il monitoraggio continuo della sicurezza dei server aziendali. 
Il progetto sfrutta un'architettura a microservizi (Docker) per raccogliere passivamente report di vulnerabilità (modello Push tramite Aqua Trivy), analizzare la validità dei certificati SSL/HTTP Headers, e orchestrare gli allarmi tramite Zabbix con apertura automatica di Issue su GitLab.

## Requisiti Preliminari
- Docker e Docker Compose installati sul server host.

## Installazione e Setup

**1. Clonare il repository**
Scarica i file del progetto sul tuo server.

**2. Configurare le variabili d'ambiente (IMPORTANTE)**
Per motivi di sicurezza, le password e i token non sono inclusi nel codice. 
Devi creare un file chiamato esattamente `.env` nella root del progetto e compilarlo con i tuoi dati:

```env
# Database
DB_HOST=sygest-db
DB_USER=root
DB_PASSWORD=la_tua_password_db
DB_NAME=progetto_sygest

# Zabbix
ZABBIX_URL=http://zabbix-frontend:8080
ZABBIX_USER=Admin
ZABBIX_PWD=zabbix
ZABBIX_SERVER=zabbix-server
ZABBIX_PORT=10051

# Sicurezza API Sygest
SYGEST_API_KEY=la_tua_api_key_segreta

# Integrazione GitLab
GITLAB_URL=[https://gitlab.com](https://gitlab.com)
GITLAB_TOKEN=tuo_token_gitlab
GITLAB_PROJECT_ID=12345678