import os
import pymysql
from dotenv import load_dotenv

# Carica le variabili dal file .env se lo script viene lanciato in locale
load_dotenv()

# Dizionario per la connessione al database
DB_CONFIG = {
    'host': os.getenv('DB_HOST', 'sygest-db'),
    'user': os.getenv('DB_USER', 'root'),
    'password': os.getenv('DB_PASSWORD', 'root_pwd_sygest'),
    'database': os.getenv('DB_NAME', 'progetto_sygest'),
    'charset': 'utf8mb4',
    'cursorclass': pymysql.cursors.DictCursor
}

# Credenziali Zabbix Frontend
ZABBIX_URL = os.getenv('ZABBIX_URL', 'http://zabbix-frontend:8080')
ZABBIX_USER = os.getenv('ZABBIX_USER', 'Admin')
ZABBIX_PWD = os.getenv('ZABBIX_PWD', 'zabbix')

# Dati Zabbix Trapper
ZABBIX_SERVER = os.getenv('ZABBIX_SERVER', 'zabbix-server')
ZABBIX_PORT = int(os.getenv('ZABBIX_PORT', 10051))

# Sicurezza API
SYGEST_API_KEY = os.getenv('SYGEST_API_KEY', '')