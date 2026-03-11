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
    
    # CONFIGURAZIONE UTENTE ADMIN (DESTINATARIO E FILTRO ANTI-SPAM)
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
                # Filtro ANTI-SPAM dove imposto la Severity a 60 (esclude gli allarmi di tipo "Info").
                # In questo modo, la prima lettura massiva di CVE non spamma la casella mail.
                "severity": 60, 
                "period": "1-7,00:00-24:00" # Accetto mail 7 giorni su 7, 24 ore su 24
            }]
        )
        print("Email di destinazione associata all'utente Admin (Filtro Anti-Spam ATTIVO).")

    # CREAZIONE DELLA ACTION PER L'INVIO
    action_name = "Invia Notifiche di Sicurezza via Mail"
    # Controllo se l'Action esiste già per evitare di crearne duplicati
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

    print("\nSincronizzazione Host e configurazione Items/Triggers...")
    
    # FASE DI CREAZIONE E AGGIORNAMENTO
    for target in db_targets:
        hostname = target['hostname']
        db_hostnames.append(hostname) # Salvo i nomi per la fase di cancellazione successiva
        
        # Se un host va in errore, Zabbix va in crash ma passa al prossimo.
        try:
            # In Zabbix, status 0 significa "Monitorato" e 1 significa "Non Monitorato".
            # Nel mio DB è l'opposto (1=ON, 0=OFF), quindi applico l'inversione logica.
            desired_status = 0 if target['active'] else 1 
            host_id = None

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
                
            # Se invece l'host esiste già in Zabbix, controllo se lo stato (ON/OFF) sia cambiato
            else:
                host_id = zbx_host_dict[hostname]['hostid']
                zbx_status = int(zbx_host_dict[hostname]['status'])
                if zbx_status != desired_status:
                    # Se c'è una discrepanza tra il mio DB e Zabbix, aggiorno Zabbix
                    api.host.update(hostid=host_id, status=desired_status)
                    print(f"Stato aggiornato per '{hostname}'")

            # --- FUNZIONE DI AIUTO PER GLI ITEM ---
            # Questa funzione risolve il bug di Zabbix costruendo dinamicamente i parametri
            # per evitare di mandare master_itemid vuoti che farebbero crashare le API
            def create_or_update_item(name, key_, item_type, val_type, master_id=None, prep=None):
                existing = api.item.get(filter={"key_": key_}, hostids=host_id)
                
                # Prendo i parametri base richiesti
                params = {
                    "name": name,
                    "type": item_type,
                    "value_type": val_type
                }
                # Aggiungo i parametri opzionali SOLO se esistono
                if master_id is not None:
                    params["master_itemid"] = master_id
                if prep is not None:
                    params["preprocessing"] = prep

                if existing:
                    # L'Item esiste gia', quindi lo aggiorno
                    params["itemid"] = existing[0]['itemid']
                    api.item.update(**params)
                    return existing[0]['itemid']
                else:
                    # L'Item non esiste, lo creo agganciandolo all'host corrente
                    params["hostid"] = host_id
                    params["key_"] = key_
                    new_item = api.item.create(**params)
                    return new_item['itemids'][0]

            # --- CREAZIONE TRAPPER ITEMS ---
            # type = 2 indica che stiamo creando un Zabbix trapper item
            # value_type = 4 vuole dire che è di tipo text
            i_ssl_id = create_or_update_item("JSON - SSL", "sygest.ssl_headers", 2, 4)
            i_vuln_id = create_or_update_item("JSON - Vuln", "sygest.vuln", 2, 4)
            
            # --- CREAZIONE DEPENDENT ITEMS ---            
            # Item dipendenti dall'SSL
            # type = 18 vuol dire che stiamo creando un Dependent Item
            create_or_update_item(
                "SSL: Giorni scadenza CA",  # Il nome visibile dell'Item nell'interfaccia di Zabbix
                "ssl.days_left",            # La chiave univoca interna dell'Item per Zabbix
                18,                         # type = 18 indica a Zabbix che questo è un "Dependent Item"
                3,                          # value_type = 3 indica un "Numerico Intero". Fondamentale per fare i calcoli matematici nei Trigger
                i_ssl_id,                   # L'ID del Master Item (il Trapper che ha ricevuto il JSON intero) a cui questo item è agganciato                    
                [
                    # Definisco lo step di "Preprocessing" per dire a Zabbix come estrarre il dato
                    {
                        "type": 12,                              # type = 12 indica il metodo "JSONPath"
                        "params": "$.new_patched_count",         # Il percorso esatto nel JSON dove si trova il numero
                        "error_handler": 0,                      # 0 = Default (Requisito obbligatorio imposto dalle API di Zabbix 7.0 in poi)
                        "error_handler_params": ""
                    }
                ]
            )
            create_or_update_item(
                "SSL: Thumbprint", # Il nome visibile dell'Item nell'interfaccia di Zabbix
                "ssl.thumbprint",  # La chiave univoca interna dell'Item per Zabbix
                18,                # type = 18 indica a Zabbix che questo è un "Dependent Item"
                1,                 # value_type = 4 indica un "Character"
                i_ssl_id,          # L'ID del Master Item (il Trapper che ha ricevuto il JSON intero) a cui questo item è agganciato
                [
                    {
                        "type": 12,                              # type = 12 indica il metodo "JSONPath"
                        "params": "$.new_patched_count",         # Il percorso esatto nel JSON dove si trova il numero
                        "error_handler": 0,                      # 0 = Default (Requisito obbligatorio imposto dalle API di Zabbix 7.0 in poi)
                        "error_handler_params": ""
                    }
                ]
            )

            # Item dipendenti dagli Header di Sicurezza
            # value_type = 3 vuol dire numerico intero (per fare controlli matematici)
            create_or_update_item(
                "Sicurezza Web: Totale Header mancanti", # Il nome visibile dell'Item nell'interfaccia di Zabbix
                "headers.missing_count",                 # La chiave univoca interna dell'Item per Zabbix
                18,                                      # type = 18 indica a Zabbix che questo è un "Dependent Item"
                3,                                       # value_type = 3 indica un "Numerico Intero". Fondamentale per fare i calcoli matematici nei Trigger
                i_ssl_id,                                # L'ID del Master Item (il Trapper che ha ricevuto il JSON intero) a cui questo item è agganciato
                [
                    # Definisco lo step di "Preprocessing" per dire a Zabbix come estrarre il dato
                    {
                        "type": 12,                              # type = 12 indica il metodo "JSONPath"
                        "params": "$.new_patched_count",         # Il percorso esatto nel JSON dove si trova il numero
                        "error_handler": 0,                      # 0 = Default (Requisito obbligatorio imposto dalle API di Zabbix 7.0 in poi)
                        "error_handler_params": ""
                    }
                ]
            )
            create_or_update_item(
                "Sicurezza Web: Lista Header mancanti", # Il nome visibile dell'Item nell'interfaccia di Zabbix
                "headers.missing_list",                 # La chiave univoca interna dell'Item per Zabbix
                18,                                     # type = 18 indica a Zabbix che questo è un "Dependent Item"
                4,                                      # value_type = 4 indica un "Text"
                i_ssl_id,                               # L'ID del Master Item (il Trapper che ha ricevuto il JSON intero) a cui questo item è agganciato
                [
                    # Definisco lo step di "Preprocessing" per dire a Zabbix come estrarre il dato
                    {
                        "type": 12,                              # type = 12 indica il metodo "JSONPath"
                        "params": "$.new_patched_count",         # Il percorso esatto nel JSON dove si trova il numero
                        "error_handler": 0,                      # 0 = Default (Requisito obbligatorio imposto dalle API di Zabbix 7.0 in poi)
                        "error_handler_params": ""
                    }
                ]
            )
            
            # Item dipendenti dalle Vulnerabilità
            create_or_update_item(
                "Sicurezza: Totale CVE attivi", # Il nome visibile dell'Item nell'interfaccia di Zabbix
                "vuln.total_active",            # La chiave univoca interna dell'Item per Zabbix
                18,                             # type = 18 indica a Zabbix che questo è un "Dependent Item"
                3,                              # value_type = 3 indica un "Numerico Intero". Fondamentale per fare i calcoli matematici nei Trigger
                i_vuln_id,                      # L'ID del Master Item (il Trapper che ha ricevuto il JSON intero) a cui questo item è agganciato
                [
                    # Definisco lo step di "Preprocessing" per dire a Zabbix come estrarre il dato
                    {
                        "type": 12,                              # type = 12 indica il metodo "JSONPath"
                        "params": "$.new_patched_count",         # Il percorso esatto nel JSON dove si trova il numero
                        "error_handler": 0,                      # 0 = Default (Requisito obbligatorio imposto dalle API di Zabbix 7.0 in poi)
                        "error_handler_params": ""
                    }
                ]
            )
            create_or_update_item(
                "Sicurezza: Lista nuovi CVE attivi", # Il nome visibile dell'Item nell'interfaccia di Zabbix
                "vuln.new_active_list",              # La chiave univoca interna dell'Item per Zabbix
                18,                                  # type = 18 indica a Zabbix che questo è un "Dependent Item"
                4,                                   # value_type = 4 indica un "Text"
                i_vuln_id,                           # L'ID del Master Item (il Trapper che ha ricevuto il JSON intero) a cui questo item è agganciato
                [
                    # Definisco lo step di "Preprocessing" per dire a Zabbix come estrarre il dato
                    {
                        "type": 12,                              # type = 12 indica il metodo "JSONPath"
                        "params": "$.new_patched_count",         # Il percorso esatto nel JSON dove si trova il numero
                        "error_handler": 0,                      # 0 = Default (Requisito obbligatorio imposto dalle API di Zabbix 7.0 in poi)
                        "error_handler_params": ""
                    }
                ]
            )
            create_or_update_item(
                "Sicurezza: Lista patch trovate", # Il nome visibile dell'Item nell'interfaccia di Zabbix
                "vuln.new_patched_list",          # La chiave univoca interna dell'Item per Zabbix
                18,                               # type = 18 indica a Zabbix che questo è un "Dependent Item"
                4,                                # value_type = 4 indica un "Text"
                i_vuln_id,                        # L'ID del Master Item (il Trapper che ha ricevuto il JSON intero) a cui questo item è agganciato
                [
                    # Definisco lo step di "Preprocessing" per dire a Zabbix come estrarre il dato
                    {
                        "type": 12,                              # type = 12 indica il metodo "JSONPath"
                        "params": "$.new_patched_count",         # Il percorso esatto nel JSON dove si trova il numero
                        "error_handler": 0,                      # 0 = Default (Requisito obbligatorio imposto dalle API di Zabbix 7.0 in poi)
                        "error_handler_params": ""
                    }
                ]
            )
            
            # Nuovi Item per contare i CVE in modo da poter far scattare i trigger giusti
            create_or_update_item(
                "Sicurezza: Nuovi CVE (Count)", # Il nome visibile dell'Item nell'interfaccia di Zabbix
                "vuln.new_active_count",        # La chiave univoca interna dell'Item per Zabbix
                18,                             # type = 18 indica a Zabbix che questo è un "Dependent Item"
                3,                              # value_type = 3 indica un "Numerico Intero". Fondamentale per fare i calcoli matematici nei Trigger
                i_vuln_id,                      # L'ID del Master Item (il Trapper che ha ricevuto il JSON intero) a cui questo item è agganciato
                [
                    # Definisco lo step di "Preprocessing" per dire a Zabbix come estrarre il dato
                    {
                        "type": 12,                              # type = 12 indica il metodo "JSONPath"
                        "params": "$.new_patched_count",         # Il percorso esatto nel JSON dove si trova il numero
                        "error_handler": 0,                      # 0 = Default (Requisito obbligatorio imposto dalle API di Zabbix 7.0 in poi)
                        "error_handler_params": ""
                    }
                ]
            )
            create_or_update_item(
                "Sicurezza: Nuovi CVE patchati (Count)", # Il nome visibile dell'Item nell'interfaccia di Zabbix
                "vuln.new_patched_count",                # La chiave univoca interna dell'Item per Zabbix
                18,                                      # type = 18 indica a Zabbix che questo è un "Dependent Item"
                3,                                       # value_type = 3 indica un "Numerico Intero". Fondamentale per fare i calcoli matematici nei Trigger
                i_vuln_id,                               # L'ID del Master Item (il Trapper che ha ricevuto il JSON intero) a cui questo item è agganciato
                [
                    # Definisco lo step di "Preprocessing" per dire a Zabbix come estrarre il dato
                    {
                        "type": 12,                              # type = 12 indica il metodo "JSONPath"
                        "params": "$.new_patched_count",         # Il percorso esatto nel JSON dove si trova il numero
                        "error_handler": 0,                      # 0 = Default (Requisito obbligatorio imposto dalle API di Zabbix 7.0 in poi)
                        "error_handler_params": ""
                    }
                ]
            )

            # --- FUNZIONE DI AIUTO PER I TRIGGERS ---
            # Questa funzione crea un trigger se non esiste, o lo aggiorna se le regole (expression/priority) sono cambiate
            def create_or_update_trigger(desc, expr, prio):
                # Interrogo Zabbix per vedere se su questo specifico Host c'è già un trigger con questa esatta descrizione
                existing = api.trigger.get(filter={"description": desc}, hostids=host_id)
                
                if existing:
                    # Se il trigger esiste già, tento di sovrascrivere la sua logica e la sua priorità
                    try:
                        api.trigger.update(triggerid=existing[0]['triggerid'], expression=expr, priority=prio)
                    except Exception:
                        # Zabbix ha un comportamento particolare nelle API: se gli mandi un comando di update
                        # con un'espressione che è già perfettamente identica a quella che ha in pancia, 
                        # lui va in panico e lancia un'eccezione. Con questo pass ignoriamo il falso errore in modo pulito.
                        pass 
                else:
                    # Se non trova nessun trigger con quel nome, chiama l'API di creazione per farlo da zero
                    api.trigger.create(description=desc, expression=expr, priority=prio)

            # --- CREAZIONE DEI TRIGGERS ---
            # Passo l'expression e il livello di gravità che va da 1 (Info) a 5 (Disaster).
            create_or_update_trigger(
                f"Allarme: Certificato SSL in scadenza per {{HOST.NAME}}", 
                f"last(/{hostname}/ssl.days_left)<30",
                4
            )
            create_or_update_trigger(f"Info: Thumbprint SSL cambiato per {{HOST.NAME}}", f"last(/{hostname}/ssl.thumbprint)<>last(/{hostname}/ssl.thumbprint,#2)", 1)
            
            # Trigger per gli Header di Sicurezza
            create_or_update_trigger(
                f"Peggioramento Web: Aumentati gli header di sicurezza mancanti su {{HOST.NAME}}", 
                f"length(last(/{hostname}/headers.missing_list))>=0 and last(/{hostname}/headers.missing_count)>last(/{hostname}/headers.missing_count,#2)", 
                4
            )
            create_or_update_trigger(
                f"Miglioramento Web: Diminuiti gli header di sicurezza mancanti su {{HOST.NAME}}", 
                f"length(last(/{hostname}/headers.missing_list))>=0 and last(/{hostname}/headers.missing_count)<last(/{hostname}/headers.missing_count,#2)", 
                3
            )
            create_or_update_trigger(
                f"Prima lettura Web: Header di sicurezza mancanti su {{HOST.NAME}}", 
                f"length(last(/{hostname}/headers.missing_list))>=0 and count(/{hostname}/headers.missing_count,#1)>=1 and count(/{hostname}/headers.missing_count,#2)=1", 
                3
            )
            
            # Trigger per le Vulnerabilita e CVE
            # CASO 1: Tra 1 e 20 CVE Nuovi senza patch (High) -> Scatta l'Allarme e manda la mail (Priority 4)
            create_or_update_trigger(
                f"Allarme: Rilevati nuovi CVE critici su {{HOST.NAME}}", 
                f"last(/{hostname}/vuln.new_active_count)>0 and last(/{hostname}/vuln.new_active_count)<=20", 
                4
            )
            
            # CASO 2: Tra 1 e 20 Patch Nuove trovate (Warning) -> Scatta l'Allarme e manda la mail (Priority 2)
            create_or_update_trigger(
                f"Risoluzione: Trovate nuove patch di sicurezza per {{HOST.NAME}}", 
                f"last(/{hostname}/vuln.new_patched_count)>0 and last(/{hostname}/vuln.new_patched_count)<=20", 
                2
            )
            
            # CASO 3: Oltre 20 CVE (Prima Lettura Server) -> Scatta a livello Info (Priority 1)
            # La regola "Severity 60" sull'utente Admin bloccherà l'invio della mail salvandoti dallo spam!
            create_or_update_trigger(
                f"Info: Prima lettura massiva CVE su {{HOST.NAME}}", 
                f"last(/{hostname}/vuln.new_active_count)>20", 
                1
            )

        except Exception as e:
            # Catturo l'errore del singolo host per evitare che blocchi gli altri host successivi
            print(f"Errore critico durante la sincronizzazione dell'host '{hostname}': {e}")
            continue

    # FASE DI PULIZIA
    # Ora ciclo sugli host che sono in Zabbix. Se ne trovo uno che NON è più nel mio DB locale,
    # significa che l'ho cancellato tramite il mio host_manager quindi lo elimino anche da Zabbix
    for zbx_hostname, zbx_data in zbx_host_dict.items():
        if zbx_hostname not in db_hostnames:
            try:
                api.host.delete(zbx_data['hostid'])
                print(f"Host '{zbx_hostname}' eliminato da Zabbix perche' non piu' presente nel DB")
            except Exception as e:
                print(f"Impossibile eliminare l'host '{zbx_hostname}': {e}")

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