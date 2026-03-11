# Importo la libreria pymysql per il mio DB per allineare gli host
import pymysql

# Importo la classe ZabbixAPI dalla libreria zabbix_utils. Questa mi permette di 
# comandare Zabbix inviando richieste HTTP (JSON-RPC)
from zabbix_utils import ZabbixAPI

# Definisco le credenziali per collegarmi al mio database locale nel container sygest-db
DB_CONFIG = {
    'host': 'sygest-db', 
    'user': 'root', 
    'password': 'root_pwd_sygest',
    'database': 'progetto_sygest', 
    'charset': 'utf8mb4',
    'cursorclass': pymysql.cursors.DictCursor # Chiedo i risultati come dizionari per facilitarne la lettura
}

# Definisco le credenziali dell'utente amministratore di Zabbix
# ZABBIX_URL punta al frontend web esposto dal container docker
ZABBIX_URL = "http://zabbix-frontend:8080"
ZABBIX_USER = "Admin"
ZABBIX_PWD = "zabbix"

def configure_zabbix_alerts(api):
    print("Configurazione Zabbix in corso...")
    
    # CONFIGURAZIONE MEDIA TYPE (IL MITTENTE)
    # Cerco tramite API il "canale di comunicazione" chiamato "Email"
    media_types = api.mediatype.get(search={"name": "Email"})
    if media_types:
        # Prendo l'ID interno che Zabbix usa per identificare questo media type
        media_id = media_types[0]['mediatypeid']
        
        # Aggiorno i parametri del Media Type sovrascrivendoli con i dati di Gmail
        api.mediatype.update(
            mediatypeid=media_id,
            status=0,                     # Forzo lo status a 0 (Enabled)
            smtp_server="smtp.gmail.com",
            smtp_port="587",
            smtp_helo="gmail.com",
            smtp_email="arashpreetsingh177@gmail.com",
            smtp_security=1,              # Nelle API di Zabbix, 1 = STARTTLS, 2 = SSL/TLS.
            smtp_authentication=1,        # 1 = Richiede Username e Password
            username="arashpreetsingh177@gmail.com",
            passwd="vpfx vhwc wcdp uyau"  # Password specifica per le app generata da Google
        )
        print("Server SMTP (Gmail) configurato e ATTIVATO su Zabbix.")
    
    # CONFIGURAZIONE UTENTE ADMIN (DESTINATARIO)
    # Cerco l'utente "Admin" nel sistema
    users = api.user.get(filter={"username": "Admin"})
    if users and media_types:
        admin_id = users[0]['userid']
        
        # Assegno all'Admin il Media Type "Email" appena configurato, dicendogli a quale 
        # indirizzo email inviare le notifiche.
        api.user.update(
            userid=admin_id,
            medias=[{
                "mediatypeid": media_id,
                "sendto": ["arashpreet.singh@studenti.unipr.it"], # Destinatario
                "active": 0,    # (0 = enable)
                "severity": 63, # Per ricevere tutti i livelli di gravita'
                "period": "1-7,00:00-24:00" # Accetto mail 7 giorni su 7, 24 ore su 24
            }]
        )
        print("Email di destinazione associata all'utente Admin.")

    # CREAZIONE DELLA ACTION PER L'INVIO
    action_name = "Invia Notifiche di Sicurezza via Mail"
    # Controllo se l'Action esiste già per evitare di crearne dei duplicati
    actions = api.action.get(filter={"name": action_name})
    if not actions and users and media_types:
        
        # Definisco il template del corpo della mail, dove le variaibli tra le graffe sono dette 
        # "Macro" che Zabbix sostituirà in automatico con i dati dell'allarme nel momento in cui scatta
        message_body = (
            "ALERT DI SICUREZZA - SISTEMA SYGEST\n\n"
            "Il sistema di monitoraggio ha rilevato una variazione per il seguente target:\n"
            "Host: {HOST.NAME}\n\n"
            "{EVENT.NAME}\n"
            "Gravità: {EVENT.SEVERITY}\n"
            "Rilevato il: {EVENT.DATE} alle {EVENT.TIME}\n\n"
            "--------------------------------------------------\n"
            "DATI RILEVATI DALLO SCRIPT:\n\n"
            # Questa è la Macro contiene il testo dei CVE formattato dal mio script Python
            "{ITEM.VALUE1}\n" 
            "--------------------------------------------------\n\n"
            "Per visualizzare lo storico completo o gestire l'allarme, accedi alla dashboard di Zabbix."
        )
        
        # Creo l'Action tramite API
        api.action.create(
            name=action_name,
            eventsource=0, # L'evento scatenante è un Trigger (0)
            status=0,      # L'Action è attiva (0)
            esc_period="1h", # In caso di problemi, aspetta 1 ora prima di ripetere eventuali escalation
            operations=[{
                "operationtype": 0, # 0 = Invia un messaggio
                "opmessage_usr": [{"userid": admin_id}], # Destinatario = ADMIN
                "opmessage": {
                    "default_msg": 0, # Disabilito il messaggio di default di Zabbix per usare il mio
                    "subject": "[{EVENT.SEVERITY}] {EVENT.NAME}", # Oggetto della mail
                    "message": message_body,                      # Corpo della mail definito sopra
                    "mediatypeid": media_id                       # Usa il canale Gmail
                }
            }]
        )
        print("Action di allarme creata con template formattato")

# Questa funzione sincronizza Zabbix con il mio Database
def sync_hosts(api, db_targets):
    # Cerco il gruppo "Sygest Targets" e se non esiste lo creo.
    groups = api.hostgroup.get(filter={"name": "Sygest Targets"})
    group_id = groups[0]['groupid'] if groups else api.hostgroup.create(name="Sygest Targets")['groupids'][0]

    # Estraggo tutti gli host attualmente configurati in Zabbix dentro questo gruppo
    # Uso un dizionario ({nome_host: dati_host}) per fare confronti incrociati
    zabbix_hosts = api.host.get(groupids=group_id, output=["hostid", "host", "status"])
    # Prendo un elemento alla volta dalla lista e quell'elemento prende 
    # il valore che sta sotto la voce 'host'
    zbx_host_dict = {h['host']: h for h in zabbix_hosts}
    
    db_hostnames = []

    print("\nSincronizzazione Host...")
    
    # FASE DI CREAZIONE E AGGIORNAMENTO
    for target in db_targets:
        hostname = target['hostname']
        db_hostnames.append(hostname) # Salvo i nomi per la fase di cancellazione successiva
        
        # In Zabbix, status 0 significa "Monitorato" e 1 significa "Non Monitorato".
        # Nel mio DB è l'opposto (1=ON, 0=OFF), quindi applico l'inversione logica.
        desired_status = 0 if target['active'] else 1 

        # Se l'host del database non esiste in Zabbix, procedo alla creazione
        if hostname not in zbx_host_dict:
            print(f"Creazione di '{hostname}' e dei suoi Items/Triggers...")
            
            # Creo l'Host
            # L'interfaccia richiede un IP perché io uso item di tipo "Trapper", non agent
            new_host = api.host.create(
                host=hostname, 
                status=desired_status, 
                groups=[{"groupid": group_id}],
                interfaces=[
                    {
                        "type": 1, 
                        "main": 1, 
                        "useip": 1, 
                        "ip": "127.0.0.1", 
                        "dns": "", 
                        "port": "10050"
                    }
                ]
            )
            host_id = new_host['hostids'][0]
            
            # --- CREAZIONE TRAPPER ITEMS ---
            i_ssl = api.item.create(
                name="JSON - SSL", 
                key_="sygest.ssl_headers", 
                hostid=host_id, 
                type=2, # type = 2 indica che stiamo creando un Zabbix trapper item
                value_type=4 # value_type = 4 vuole dire che sia d tipo text
            )
            i_vuln = api.item.create(
                name="JSON - Vuln", 
                key_="sygest.vuln", 
                hostid=host_id, 
                type=2, # type = 2 indica che stiamo creando un Zabbix trapper item
                value_type=4 # value_type = 4 vuole dire che sia d tipo text
            )
            
            # --- CREAZIONE DEPENDENT ITEMS ---            
            # Item dipendenti dall'SSL
            api.item.create(
                name="SSL: Giorni scadenza CA", 
                key_="ssl.days_left", 
                hostid=host_id, 
                type=18, # type = 18 vuol dire che stiamo creando un Dependent Item
                value_type=3, 
                master_itemid=i_ssl['itemids'][0], # si aggancia al Master Item
                preprocessing=[
                    {
                        "type": 12, # usa il JSONPath per estrarre la singola variabile
                        "params": "$.ssl.days_left", 
                        "error_handler": 0, # obbligatorio dopo Zabbix 7.0
                        "error_handler_params": ""
                    }
                ]
            )
            api.item.create(
                name="SSL: Thumbprint", 
                key_="ssl.thumbprint", 
                hostid=host_id, 
                type=18, # type = 18 vuol dire che stiamo creando un Dependent Item
                value_type=1, 
                master_itemid=i_ssl['itemids'][0], # si aggancia al Master Item
                preprocessing=[
                    {
                        "type": 12, # usa il JSONPath per estrarre la singola variabile
                        "params": "$.ssl.thumbprint", 
                        "error_handler": 0, # obbligatorio dopo Zabbix 7.0
                        "error_handler_params": ""
                    }
                ]
            )

            # Item dipendenti dagli Header di Sicurezza
            api.item.create(
                name="Sicurezza Web: Totale Header mancanti", 
                key_="headers.missing_count", 
                hostid=host_id, 
                type=18, # type = 18 vuol dire che stiamo creando un Dependent Item
                value_type=3, # value_type = 3 vuol dire numerico intero (per fare controlli matematici)
                master_itemid=i_ssl['itemids'][0], # si aggancia al Master Item (sygest.ssl_headers)
                preprocessing=[
                    {
                        "type": 12, # usa il JSONPath per estrarre la singola variabile
                        "params": "$.headers.missing_count", 
                        "error_handler": 0, # obbligatorio dopo Zabbix 7.0
                        "error_handler_params": ""
                    }
                ]
            )
            api.item.create(
                name="Sicurezza Web: Lista Header mancanti", 
                key_="headers.missing_list", 
                hostid=host_id, 
                type=18, # type = 18 vuol dire che stiamo creando un Dependent Item
                value_type=4, # value_type = 4 vuol dire testo
                master_itemid=i_ssl['itemids'][0], # si aggancia al Master Item
                preprocessing=[
                    {
                        "type": 12, # usa il JSONPath per estrarre la singola variabile
                        "params": "$.headers.missing_list", 
                        "error_handler": 0, # obbligatorio dopo Zabbix 7.0
                        "error_handler_params": ""
                    }
                ]
            )
            
            # Item dipendenti dalle Vulnerabilità
            api.item.create(
                name="Sicurezza: Totale CVE attivi", 
                key_="vuln.total_active", 
                hostid=host_id,
                type=18, value_type=3, 
                master_itemid=i_vuln['itemids'][0], 
                preprocessing=[
                    {
                        "type": 12, # usa il JSONPath per estrarre la singola variabile
                        "params": "$.total_active",
                        "error_handler": 0, # obbligatorio dopo Zabbix 7.0
                        "error_handler_params": ""
                    }
                ]
            )
            api.item.create(
                name="Sicurezza: Lista nuovi CVE attivi", 
                key_="vuln.new_active_list", 
                hostid=host_id, 
                type=18, 
                value_type=4, 
                master_itemid=i_vuln['itemids'][0], 
                preprocessing=[
                    {
                        "type": 12, # usa il JSONPath per estrarre la singola variabile
                        "params": "$.new_active_text", 
                        "error_handler": 0, # obbligatorio dopo Zabbix 7.0
                        "error_handler_params": ""
                    }
                ]
            )
            api.item.create(
                name="Sicurezza: Lista patch trovate",
                key_="vuln.new_patched_list", 
                hostid=host_id, 
                type=18, 
                value_type=4, 
                master_itemid=i_vuln['itemids'][0], 
                preprocessing=[
                    {
                        "type": 12, # usa il JSONPath per estrarre la singola variabile
                        "params": "$.new_patched_text", 
                        "error_handler": 0, # obbligatorio dopo Zabbix 7.0
                        "error_handler_params": ""
                    }
                ]
            )

            # --- CREAZIONE DEI TRIGGERS ---
            # Passo lexpression e il livello di gravità che va da 1 (Info) a 5 (Disaster).
            api.trigger.create(
                description=f"Allarme: Certificato SSL in scadenza per {{HOST.NAME}}", 
                expression=f"last(/{hostname}/ssl.days_left)<30", 
                priority=4
            )
            api.trigger.create(
                description=f"Info: Thumbprint SSL cambiato per {{HOST.NAME}}", 
                expression=f"last(/{hostname}/ssl.thumbprint)<>last(/{hostname}/ssl.thumbprint,#2)", 
                priority=1
            )
            
            # Trigger per gli Header di Sicurezza
            api.trigger.create(
                description=f"Peggioramento Web: Aumentati gli header di sicurezza mancanti su {{HOST.NAME}}", 
                expression=f"last(/{hostname}/headers.missing_count)>last(/{hostname}/headers.missing_count,#2)", 
                priority=3
            )
            api.trigger.create(
                description=f"Peggioramento Web: Aumentati gli header di sicurezza mancanti su {{HOST.NAME}}", 
                expression=f"length(last(/{hostname}/headers.missing_list))>=0 and last(/{hostname}/headers.missing_count)>last(/{hostname}/headers.missing_count,#2)", 
                priority=3
            )
            api.trigger.create(
                description=f"Miglioramento Web: Diminuiti gli header di sicurezza mancanti su {{HOST.NAME}}", 
                expression=f"length(last(/{hostname}/headers.missing_list))>=0 and last(/{hostname}/headers.missing_count)<last(/{hostname}/headers.missing_count,#2)", 
                priority=1
            )
            api.trigger.create(
                description = f"Prima lettura Web: Header di sicurezza mancanti su {{HOST.NAME}}",
                expression=f"length(last(/{hostname}/headers.missing_list))>=0 and count(/{hostname}/headers.missing_count,#1)>=1 and count(/{hostname}/headers.missing_count,#2)=1",
                priority = 3
            )
            api.trigger.create(
                description=f"Risoluzione: Trovate nuove patch di sicurezza per {{HOST.NAME}}", 
                expression=f"length(last(/{hostname}/vuln.new_patched_list))>0", 
                priority=1
            )
            
        # Se invece l'host esiste già in Zabbix, controllo se lo stato (ON/OFF) è cambiato
        else:
            zbx_status = int(zbx_host_dict[hostname]['status'])
            if zbx_status != desired_status:
                # Se c'è una discrepanza tra il mio DB e Zabbix, aggiorno Zabbix
                api.host.update(hostid=zbx_host_dict[hostname]['hostid'], status=desired_status)
                print(f"Stato aggiornato per '{hostname}'")

    # FASE DI PULIZIA
    # Ora ciclo sugli host che sono in Zabbix. Se ne trovo uno che NON è più nel mio DB locale,
    # significa che l'ho cancellato tramite il mio host_manager quindi lo elimino anche da Zabbix
    for zbx_hostname, zbx_data in zbx_host_dict.items():
        if zbx_hostname not in db_hostnames:
            api.host.delete(zbx_data['hostid'])
            print(f"Host '{zbx_hostname}' eliminato da Zabbix perche' non piu' presente nel DB")

def main():
    connection = None
    zapi = None
    try:
        # Apro la connessione al database locale per leggere lo stato desiderato
        connection = pymysql.connect(**DB_CONFIG)
        with connection.cursor() as cursor:
            cursor.execute("SELECT id, hostname, active FROM targets")
            db_targets = cursor.fetchall()

        print("\n=== AVVIO SINCRONIZZAZIONE ZABBIX ===")
        # Avvio la connessione alle API del Server Zabbix e mi loggo come Admin
        zapi = ZabbixAPI(url=ZABBIX_URL)
        zapi.login(user=ZABBIX_USER, password=ZABBIX_PWD)
        
        # Eseguo i due motori di configurazione sequenzialmente
        configure_zabbix_alerts(zapi)
        sync_hosts(zapi, db_targets)
        
        print("\nSincronizzazione completata con successo!\n")

    except Exception as e:
        print(f"\nErrore di sincronizzazione: {e}\n")
    finally:
        if connection: connection.close()
        if zapi: zapi.logout()

if __name__ == "__main__":
    main()