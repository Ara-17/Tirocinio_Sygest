import socket
import ssl
import hashlib # permette di calcolare il thumbprint del certificato.
import json # serve per convertire i dati in un formato compatibile con Zabbix
import subprocess # permette di eseguire comandi del sistema operativo (come shcheck)
import sys # permette di recuperare l'eseguibile Python corrente
import pymysql
from datetime import datetime

# Importo le classi ufficiali della libreria Zabbix per inviare dati in modalità passiva
from zabbix_utils import Sender, ItemValue

# Configuro i parametri di connessione al database locale.
# Uso 'sygest-db' come host perché, trovandoci dentro una rete Docker, 
# il nome del container funge automaticamente da indirizzo IP (Risoluzione DNS interna).
DB_CONFIG = {
    'host': 'sygest-db',
    'user': 'root',
    'password': 'root_pwd_sygest',
    'database': 'progetto_sygest',
    'charset': 'utf8mb4',
    # Chiedo a pymysql di restituirmi i risultati come dizionari per poter usare i nomi delle colonne
    'cursorclass': pymysql.cursors.DictCursor 
}

# Configuro i parametri del server Zabbix verso cui passare i dati.
ZABBIX_SERVER = 'zabbix-server'
ZABBIX_PORT = 10051 # È la porta standard usata da Zabbix per ricevere i dati dai Trapper

# Definisco una funzione per estrarre tutti i dettagli del certificato SSL di un dominio
def get_ssl_details(hostname):
    # la funzione _create_unverified_context() ignora gli errori e se il certificato è scaduto, 
    # il contesto standard rifiuterebbe la connessione e non potrei leggere di quanti giorni è scaduto
    contexts = [ssl.create_default_context(), ssl._create_unverified_context()]
    
    for context in contexts:
        try:
            # Imposto un timeout di 5 secondi per non bloccare lo script se il sito è offline.
            with socket.create_connection((hostname, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    # ottengo il certificato presentato dal server
                    cert = ssock.getpeercert()
                    
                    # Calcolo il thumbprint" e prendo il certificato in formato binario,
                    # lo passo all'algoritmo di hashing SHA-256 e lo converto in stringa esadecimale
                    thumbprint = hashlib.sha256(ssock.getpeercert(binary_form=True)).hexdigest().upper()
                    
                    # Estraggo la data di scadenza (chiave 'notAfter') e la converto in un oggetto datetime
                    # dicendo a Python il formato in cui è scritta ("Mese Giorno Ora Anno Fuso")
                    expire_date = datetime.strptime(cert['notAfter'], "%b %d %H:%M:%S %Y %Z")
                    
                    # Calcolo la differenza tra la data di scadenza e la data di oggi per ottenere i giorni rimanenti
                    days_left = (expire_date - datetime.now()).days

                    # Ritorno un dizionario
                    return {
                        "expire_date": expire_date.strftime("%Y-%m-%d %H:%M:%S"),
                        "days_left": days_left,
                        "thumbprint": thumbprint,
                        "verified": context.check_hostname # True se il certificato è verificato, False se ho usato il contesto unverified
                    }
        except Exception:
            # Se la connessione fallisce perchè magari il certificato non è valido, passo al secondo metodo
            continue
            
    return {"error": "SSL Connection failed"}

# Funzione per analizzare gli Header HTTPS di sicurezza sfruttando un tool esterno (shcheck)
def get_headers_with_shcheck(hostname):
    try:
        # Uso 'subprocess.run' per eseguire il tool shcheck come se stessi scrivendo nel terminale.
        result = subprocess.run(
            [
                sys.executable,        # Uso lo stesso Python che sta eseguendo questo script
                "-m", "shcheck.shcheck", # Richiamo il modulo shcheck installato tramite pip
                "-j",                  # -j dico a shcheck di restituirmi i risultati in formato JSON
                "-g", "-x", "-i",      # Disabilito alcuni controlli marginali per velocizzare l'esecuzione
                f"https://{hostname}"  # Il target da analizzare
            ],
            capture_output=True,       # non stampo a video l'output
            text=True, 
            timeout=15                 # Imposto un timeout massimo di 15 secondi per evitare che lo script si blocchi all'infinito
        )
        
        # Pulisco l'output da eventuali spazi vuoti iniziali e finali
        output = result.stdout.strip()
        
        # Se la stringa inizia con '{', significa che il tool mi ha restituito un JSON valido
        # Lo converto da stringa a dizionario Python tramite json.loads()
        if output.startswith('{'): 
            return json.loads(output)
            
    except Exception as e:
        pass
        
    return {"error": "shcheck failed"}

def run_monitoring():
    connection = None
    try:
        # Mi collego al database passando i parametri del DB_CONFIG tramite **
        connection = pymysql.connect(**DB_CONFIG)
        with connection.cursor() as cursor:
            # Chiedo al database l'elenco dei soli target che ho impostato come accesi (active = 1)
            cursor.execute("SELECT hostname FROM targets WHERE active = 1")
            targets = cursor.fetchall()
            
            # Inizializzo l'oggetto 'Sender' che si occuperà di spedire i dati a Zabbix
            sender = Sender(server=ZABBIX_SERVER, port=ZABBIX_PORT)

            # Itero tutti gli host trovati nel database
            for target in targets:
                hostname = target['hostname']
                print(f"\nZabbix Push SSL & Headers: {hostname}")

                # Chiamo le mie due funzioni per recuperare i dati dell'host corrente
                ssl_info = get_ssl_details(hostname)
                header_data = get_headers_with_shcheck(hostname)

                # Creo una lista vuota per raccogliere gli header di sicurezza che mancano
                missing_headers = []
                
                # Se shcheck non ha generato errori, analizzo il dizionario che mi ha restituito
                if "error" not in header_data:
                    for key, value in header_data.items():
                        # Cerco il blocco che contiene la lista "missing" (gli header assenti)
                        if isinstance(value, dict) and "missing" in value:
                            missing_headers = value.get("missing", [])
                            break

                # unisco le informazioni dell'SSL e quelle degli Header
                report = {
                    "ssl": ssl_info,
                    "missing_headers": missing_headers,
                    "missing_count": len(missing_headers) # Conto quanti header mancano
                }

                # Creo un oggetto 'ItemValue', il formato richiesto da Zabbix per ricevere i dati.
                # Richiede il nome dell'Host in Zabbix, la "Key" dell'Item, e il Valore che trasformo in stringa JSON
                packet = [ItemValue(hostname, 'sygest.ssl_headers', json.dumps(report))]
                
                # Invio il pacchetto tramite la rete a Zabbix
                result = sender.send(packet)
                print(f"Dati inviati a Zabbix: {result}")

    except Exception as e:
        print(f"Errore critico: {e}")
    finally:
        if connection: 
            connection.close()

if __name__ == "__main__":
    run_monitoring()