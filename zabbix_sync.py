import pymysql
from zabbix_utils import ZabbixAPI

# Imposto i dati per il collegamento al database locale
DB_CONFIG = {
    'host': 'sygest-db', 
    'user': 'root', 
    'password': 'root_pwd_sygest',
    'database': 'progetto_sygest', 
    'charset': 'utf8mb4',
    'cursorclass': pymysql.cursors.DictCursor
}

ZABBIX_URL = "http://zabbix-frontend:8080"
ZABBIX_USER = "Admin"
ZABBIX_PWD = "zabbix"

def configure_zabbix_alerts(api):
    print("Inizio la configurazione di Zabbix e delle mail")
    
    # Cerco il tipo di media Email presente di default su Zabbix
    media_types = api.mediatype.get(search={"name": "Email"})
    
    if media_types:
        media_id = media_types[0]['mediatypeid']
        
        # Inserisco i dati del server SMTP di Google per far partire i messaggi
        api.mediatype.update(
            mediatypeid=media_id, 
            status=0, 
            smtp_server="smtp.gmail.com", 
            smtp_port="587",
            smtp_helo="gmail.com", 
            smtp_email="arashpreetsingh177@gmail.com",
            smtp_security=1, 
            smtp_authentication=1, 
            username="arashpreetsingh177@gmail.com",
            passwd="vpfx vhwc wcdp uyau"
        )
    
    # Prendo l utente Admin e gli associo la casella di posta configurata sopra
    users = api.user.get(filter={"username": "Admin"})
    
    if users and media_types:
        admin_id = users[0]['userid']
        
        user_media = {
            "mediatypeid": media_id, 
            "sendto": ["arashpreet.singh@studenti.unipr.it"], 
            "active": 0, 
            "severity": 63, 
            "period": "1-7,00:00-24:00"
        }
        
        api.user.update(userid=admin_id, medias=[user_media])


    # Funzione di supporto per generare il corpo della mail con la formattazione esatta richiesta
    def genera_corpo_mail(titolo_header):
        return (
            f"{titolo_header}\n\n"
            "Il sistema di monitoraggio ha rilevato una variazione per il seguente target:\n"
            "Host: {HOST.NAME}\n\n"
            "{EVENT.NAME}\n"
            "Gravità: {EVENT.SEVERITY}\n"
            "Rilevato il: {EVENT.DATE} alle {EVENT.TIME}\n\n"
            "--------------------------------------------------\n"
            "DATI RILEVATI DALLO SCRIPT:\n\n"
            "{ITEM.VALUE1}\n" 
            "--------------------------------------------------\n\n"
            "Per visualizzare lo storico completo o gestire l'allarme, accedi alla dashboard di Zabbix."
        )

    # Ora creo azioni separate in base alla severita del trigger usando il nuovo layout
    
    # AZIONE 1 - AVVISI INFORMATIVI Prima lettura o Miglioramenti
    azione_info = "Invia Notifiche Informative e Prima Scansione"
    if not api.action.get(filter={"name": azione_info}):
        corpo_info = genera_corpo_mail("INFO DI SISTEMA - SYGEST")
        
        # Filtro conditiontype 4 indica la Severity
        # operator 0 significa Equal
        # value 1 significa Information
        filtro = {
            "evaltype": 0,
            "conditions": [{"conditiontype": 4, "operator": 0, "value": "1"}]
        }
        
        operazione = {
            "operationtype": 0, 
            "opmessage_usr": [{"userid": admin_id}],
            "opmessage": {"default_msg": 0, "subject": "INFO {EVENT.NAME}", "message": corpo_info, "mediatypeid": media_id}
        }
        
        api.action.create(name=azione_info, eventsource=0, status=0, esc_period="1h", filter=filtro, operations=[operazione])


    # AZIONE 2 - VULNERABILITA CON PATCH
    azione_patch = "Invia Avviso Nuove Patch Disponibili"
    if not api.action.get(filter={"name": azione_patch}):
        corpo_patch = genera_corpo_mail("AVVISO AGGIORNAMENTO - SYGEST")
        
        # value 3 significa Warning
        filtro = {
            "evaltype": 0,
            "conditions": [{"conditiontype": 4, "operator": 0, "value": "3"}]
        }
        
        operazione = {
            "operationtype": 0, 
            "opmessage_usr": [{"userid": admin_id}],
            "opmessage": {"default_msg": 0, "subject": "AVVISO Patch Disponibili", "message": corpo_patch, "mediatypeid": media_id}
        }
        
        api.action.create(name=azione_patch, eventsource=0, status=0, esc_period="1h", filter=filtro, operations=[operazione])


    # AZIONE 3 - VULNERABILITA SENZA PATCH O DEGRADO WEB
    azione_grave = "Invia Allarme Critico Sicurezza"
    if not api.action.get(filter={"name": azione_grave}):
        corpo_grave = genera_corpo_mail("ALLARME CRITICO - SYGEST")
        
        # value 4 e 5 indicano High e Disaster
        filtro = {
            "evaltype": 0,
            "conditions": [
                {"conditiontype": 4, "operator": 0, "value": "4"},
                {"conditiontype": 4, "operator": 0, "value": "5"}
            ]
        }
        
        operazione = {
            "operationtype": 0, 
            "opmessage_usr": [{"userid": admin_id}],
            "opmessage": {"default_msg": 0, "subject": "CRITICO {EVENT.NAME}", "message": corpo_grave, "mediatypeid": media_id}
        }
        
        api.action.create(name=azione_grave, eventsource=0, status=0, esc_period="1h", filter=filtro, operations=[operazione])


def sync_hosts(api, db_targets):
    # Controllo se il gruppo host esiste gia
    groups = api.hostgroup.get(filter={"name": "Sygest Targets"})
    
    if groups:
        group_id = groups[0]['groupid']
    else:
        # Lo creo da zero
        nuovo_gruppo = api.hostgroup.create(name="Sygest Targets")
        group_id = nuovo_gruppo['groupids'][0]
        
    # Mi scarico tutti gli host che ci sono in questo momento per fare il confronto
    zabbix_hosts = api.host.get(groupids=group_id, output=["hostid", "host", "status"])
    
    zbx_host_dict = {}
    for h in zabbix_hosts:
        zbx_host_dict[h['host']] = h
        
    db_hostnames = []

    print("Sincronizzo gli host e creo le regole")
    
    for target in db_targets:
        hostname = target['hostname']
        db_hostnames.append(hostname)
        
        try:
            # Inverto lo stato logico perche su Zabbix 0 e acceso e 1 e spento
            if target['active']:
                desired_status = 0
            else:
                desired_status = 1
                
            host_id = None

            # Creo l host sul server monitor se e la prima volta che lo vedo
            if hostname not in zbx_host_dict:
                interfaccia = {
                    "type": 1, 
                    "main": 1, 
                    "useip": 1, 
                    "ip": "127.0.0.1", 
                    "dns": "", 
                    "port": "10050"
                }
                
                new_host = api.host.create(
                    host=hostname, 
                    status=desired_status, 
                    groups=[{"groupid": group_id}],
                    interfaces=[interfaccia]
                )
                host_id = new_host['hostids'][0]
                
            else:
                # Lo aggiorno se esiste gia ma ha lo stato sbagliato rispetto al mio db
                host_id = zbx_host_dict[hostname]['hostid']
                if int(zbx_host_dict[hostname]['status']) != desired_status:
                    api.host.update(hostid=host_id, status=desired_status)

            # Funzione interna di supporto per creare o aggiornare gli item in maniera sicura
            def create_or_update_item(name, key_, item_type, val_type, master_id=None, prep=None):
                existing = api.item.get(filter={"key_": key_}, hostids=host_id)
                
                params = {
                    "name": name, 
                    "type": item_type, 
                    "value_type": val_type
                }
                
                # Inserisco i campi opzionali nel dizionario solo se ci sono davvero
                if master_id is not None: 
                    params["master_itemid"] = master_id
                if prep is not None: 
                    params["preprocessing"] = prep

                if existing:
                    params["itemid"] = existing[0]['itemid']
                    api.item.update(**params)
                    return existing[0]['itemid']
                else:
                    params["hostid"] = host_id
                    params["key_"] = key_
                    nuovo_item = api.item.create(**params)
                    return nuovo_item['itemids'][0]

            # Creo i due Trapper principali che accolgono l intero payload Json
            i_vuln_id = create_or_update_item("JSON Vuln", "sygest.vuln", 2, 4)
            i_ssl_id = create_or_update_item("JSON SSL", "sygest.ssl_headers", 2, 4)
            
            # Genero i dependent item che estraggono solo i numeri per fare i calcoli
            def crea_dipendente_numerico(nome, chiave, json_path, master):
                regola = [{"type": 12, "params": json_path, "error_handler": 0, "error_handler_params": ""}]
                return create_or_update_item(nome, chiave, 18, 3, master, regola)
                
            crea_dipendente_numerico("Vuln First Read Flag", "vuln.is_first_read", "$.metrics.is_first_read", i_vuln_id)
            crea_dipendente_numerico("Vuln Totale CVE attivi", "vuln.total_active", "$.metrics.total_active", i_vuln_id)
            crea_dipendente_numerico("Vuln Totale CVE CON Patch", "vuln.total_with_patch", "$.metrics.total_with_patch", i_vuln_id)
            crea_dipendente_numerico("Vuln Totale CVE SENZA Patch", "vuln.total_without_patch", "$.metrics.total_without_patch", i_vuln_id)
            crea_dipendente_numerico("Vuln NUOVI CVE CON Patch", "vuln.new_with_patch_count", "$.metrics.new_with_patch_count", i_vuln_id)
            crea_dipendente_numerico("Vuln NUOVI CVE SENZA Patch", "vuln.new_without_patch_count", "$.metrics.new_without_patch_count", i_vuln_id)

            # Genero i dependent item che estraggono i testi pre formattati
            def crea_dipendente_testo(nome, chiave, json_path, master):
                regola = [{"type": 12, "params": json_path, "error_handler": 0, "error_handler_params": ""}]
                return create_or_update_item(nome, chiave, 18, 4, master, regola)

            crea_dipendente_testo("Vuln Testo Prima Lettura", "vuln.first_read_text", "$.texts.first_read_text", i_vuln_id)
            crea_dipendente_testo("Vuln Testo Nuovi CON Patch", "vuln.new_with_patch_text", "$.texts.new_with_patch_text", i_vuln_id)
            crea_dipendente_testo("Vuln Testo Nuovi SENZA Patch", "vuln.new_without_patch_text", "$.texts.new_without_patch_text", i_vuln_id)

            # Genero i dependent item per SSL e Web Security 
            crea_dipendente_numerico("SSL Giorni scadenza CA", "ssl.days_left", "$.ssl.days_left", i_ssl_id)
            crea_dipendente_testo("SSL Thumbprint", "ssl.thumbprint", "$.ssl.thumbprint", i_ssl_id)
            crea_dipendente_numerico("Sicurezza Web Totale Header mancanti", "headers.missing_count", "$.headers.missing_count", i_ssl_id)
            crea_dipendente_testo("Sicurezza Web Lista Header mancanti", "headers.missing_list", "$.headers.missing_list", i_ssl_id)


            # Funzione per inserire in sicurezza i trigger logici
            def create_or_update_trigger(desc, expr, prio):
                existing = api.trigger.get(filter={"description": desc}, hostids=host_id)
                
                if existing:
                    try: 
                        api.trigger.update(triggerid=existing[0]['triggerid'], expression=expr, priority=prio)
                    except Exception: 
                        pass 
                else:
                    api.trigger.create(description=desc, expression=expr, priority=prio)

            # Inserisco tutti i trigger necessari al funzionamento
            
            # TRIGGERS VULNERABILITA TRIVY
            
            # Prima Lettura Info
            create_or_update_trigger(
                f"Info Prima lettura massiva Trivy completata su {{HOST.NAME}}", 
                f"length(last(/{hostname}/vuln.first_read_text))>0 and last(/{hostname}/vuln.is_first_read)=1", 
                1 
            )

            # Nuovi CVE SENZA Patch Disaster
            create_or_update_trigger(
                f"CRITICO Rilevati Nuovi CVE SENZA PATCH su {{HOST.NAME}}", 
                f"length(last(/{hostname}/vuln.new_without_patch_text))>0 and last(/{hostname}/vuln.new_without_patch_count)>0", 
                5 
            )

            # Nuovi CVE CON Patch Warning
            create_or_update_trigger(
                f"Avviso Rilevati Nuovi CVE o nuove patch disponibili su {{HOST.NAME}}", 
                f"length(last(/{hostname}/vuln.new_with_patch_text))>0 and last(/{hostname}/vuln.new_with_patch_count)>0", 
                3 
            )

            # TRIGGERS WEB SECURITY E HEADER
            
            # Prima Lettura Header
            create_or_update_trigger(
                f"Prima scansione Web per {{HOST.NAME}}. Header attualmente mancanti", 
                f"length(last(/{hostname}/headers.missing_list))>=0 and count(/{hostname}/headers.missing_count,#2)=1", 
                1
            )

            # Peggioramento Header Sono spariti header di sicurezza che prima c erano scatta dal secondo invio in poi
            create_or_update_trigger(
                f"Peggioramento Web Aumentati gli header mancanti su {{HOST.NAME}}", 
                f"length(last(/{hostname}/headers.missing_list))>=0 and last(/{hostname}/headers.missing_count)>last(/{hostname}/headers.missing_count,#2) and count(/{hostname}/headers.missing_count,#2)=2", 
                4
            )

            # Miglioramento Header Il sistemista ha aggiunto delle policy corrette
            create_or_update_trigger(
                f"Miglioramento Web Ridotti gli header mancanti su {{HOST.NAME}}", 
                f"length(last(/{hostname}/headers.missing_list))>=0 and last(/{hostname}/headers.missing_count)<last(/{hostname}/headers.missing_count,#2) and count(/{hostname}/headers.missing_count,#2)=2", 
                1
            )

            # TRIGGERS SSL
            create_or_update_trigger(f"Allarme Certificato SSL in scadenza per {{HOST.NAME}}", f"last(/{hostname}/ssl.days_left)<30", 4)
            create_or_update_trigger(f"Info Thumbprint SSL cambiato per {{HOST.NAME}}", f"last(/{hostname}/ssl.thumbprint)<>last(/{hostname}/ssl.thumbprint,#2)", 1)

        except Exception as e:
            print(f"Ho riscontrato un errore durante l allineamento del server {hostname} con eccezione {e}")
            continue

    # Ultimo passaggio pulisco Zabbix eliminando gli host che l utente ha rimosso dal db
    for zbx_hostname, zbx_data in zbx_host_dict.items():
        if zbx_hostname not in db_hostnames:
            try:
                api.host.delete(zbx_data['hostid'])
            except Exception as e:
                pass

def main():
    connection = None
    zapi = None
    
    try:
        # Mi collego per pescare l intera lista dei server registrati
        connection = pymysql.connect(**DB_CONFIG)
        with connection.cursor() as cursor:
            cursor.execute("SELECT id, hostname, active FROM targets")
            db_targets = cursor.fetchall()

        print("\nAVVIO PROCEDURA DI SINCRONIZZAZIONE ZABBIX")
        zapi = ZabbixAPI(url=ZABBIX_URL)
        zapi.login(user=ZABBIX_USER, password=ZABBIX_PWD)
        
        configure_zabbix_alerts(zapi)
        sync_hosts(zapi, db_targets)
        
        print("Allineamento Zabbix terminato con successo")

    except Exception as e:
        print(f"\nCe stato un errore nella sincronizzazione generale {e}")
        
    finally:
        if connection: 
            connection.close()
        if zapi: 
            zapi.logout()

if __name__ == "__main__":
    main()