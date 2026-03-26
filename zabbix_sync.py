import pymysql
import os
from zabbix_utils import ZabbixAPI
from dotenv import load_dotenv
load_dotenv()
from config import DB_CONFIG, ZABBIX_URL, ZABBIX_USER, ZABBIX_PASSWORD

def configure_zabbix_alerts(api):
    print("Inizio la configurazione di Zabbix e delle mail")
    
    # CONFIGURAZIONE DEL CANALE GITLAB (WEBHOOK)
    gitlab_url = os.getenv('GITLAB_URL', 'https://gitlab.com')
    gitlab_token = os.getenv('GITLAB_TOKEN', '')
    gitlab_project_id = os.getenv('GITLAB_PROJECT_ID', '')
    
    media_name = "GitLab"
    
    # Script JavaScript che Zabbix usa per fare la chiamata API a GitLab
    js_webhook_script = """
    try {
        var params = JSON.parse(value);
        var req = new HttpRequest();
        req.addHeader('PRIVATE-TOKEN: ' + params.token);
        req.addHeader('Content-Type: application/json');
        
        var baseUrl = params.url + '/api/v4/projects/' + params.project_id + '/issues';
        
        // Cerco se esiste già una Issue aperta che contiene l'hostname nel titolo.
        // Usando il nome dell'host invece del titolo esatto, posso riutilizzare la stessa Issue 
        // cambiandole il titolo dinamicamente (es. da "Report" a "Peggioramento")
        var searchUrl = baseUrl + '?state=opened&search=' + encodeURIComponent(params.host) + '&in=title';
        var getResp = req.get(searchUrl);
        
        if (req.getStatus() != 200) { throw 'Ricerca issue fallita. HTTP: ' + req.getStatus(); }
        
        var issues = JSON.parse(getResp);
        var existingIid = null;
        
        // Controllo che il titolo contenga davvero l'host per evitare falsi positivi
        for (var i = 0; i < issues.length; i++) {
            if (issues[i].title.indexOf(params.host) !== -1) {
                existingIid = issues[i].iid;
                break;
            }
        }
        
        // Capisco se questa chiamata è solo una "Sincronizzazione" silenziosa (Routine)
        var isRoutine = (params.title.indexOf('Routine') !== -1);
        
        var payload = {
            title: params.title,
            labels: params.labels
        };
        
        // ESTRAZIONE VOTI PER ETICHETTE SCOPED ---
        // Il webhook legge il proprio Markdown riga per riga per cercare la tabella dei voti
        var hdrsGrade = "";
        var sslGrade = "";
        var lines = params.description.split('\\n');
        
        for (var j = 0; j < lines.length; j++) {
            if (lines[j].indexOf('| Headers Grade |') !== -1) {
                var parts = lines[j].split('|');
                if (parts.length >= 3) {
                    // Prende il testo della colonna, toglie gli spazi e isola solo la prima parola (es. "A+")
                    hdrsGrade = parts[2].trim().split(' ')[0]; 
                }
            }
            if (lines[j].indexOf('| SSL Grade |') !== -1) {
                var parts = lines[j].split('|');
                if (parts.length >= 3) {
                    sslGrade = parts[2].trim();
                }
            }
        }

        // Creo un array temporaneo per le nuove etichette dinamiche
        var customLabels = [];
        if (hdrsGrade && hdrsGrade !== 'N/A') { 
            customLabels.push("headers-grade::" + hdrsGrade); 
        }
        if (sslGrade && sslGrade !== 'N/A') { 
            customLabels.push("ssl-grade::" + sslGrade); 
        }

        // Le unisco alle etichette di base (alert, sygest, zabbix) separate da virgola
        if (customLabels.length > 0) {
            payload.labels = params.labels + "," + customLabels.join(",");
        }
        
        // Sovrascrivo il corpo della Issue SOLO se Zabbix mi ha passato il Markdown completo.
        if (params.description.indexOf('Report Summary') !== -1 || !existingIid) {
            payload.description = params.description;
        }
        
        if (existingIid !== null) {
            // L'ISSUE ESISTE
            if (isRoutine) {
                // Se è un controllo di routine e l'issue c'è già, NON faccio aggiornamenti a vuoto!
                return 'Issue presente, nessun aggiornamento necessario (Routine)';
            } else {
                // Se c'è un VERO cambiamento (Peggioramento/Miglioramento/ecc), faccio un PUT per aggiornarla
                req.put(baseUrl + '/' + existingIid, JSON.stringify(payload));
                if (req.getStatus() != 200) { throw 'Aggiornamento fallito. HTTP: ' + req.getStatus(); }
                
                // Faccio un POST per aggiungere un commento, così GitLab manda la notifica email al team!
                var notePayload = JSON.stringify({ body: "Notifica di sistema:\\nZabbix ha rilevato un evento: **" + params.title + "**" });
                var reqNote = new HttpRequest();
                reqNote.addHeader('PRIVATE-TOKEN: ' + params.token);
                reqNote.addHeader('Content-Type: application/json');
                reqNote.post(baseUrl + '/' + existingIid + '/notes', notePayload);
                
                return 'Aggiornata Issue #' + existingIid + ' e aggiunto commento';
            }
        } else {
            // L'ISSUE NON ESISTE (Cancellata per sbaglio o è la primissima scansione)
            if (!payload.description) { payload.description = params.description; }
            
            // Se la creiamo durante una routine, le diamo un titolo pulito "Report su host"
            if (isRoutine) { payload.title = "Report su " + params.host; }
            
            req.post(baseUrl, JSON.stringify(payload));
            if (req.getStatus() != 201) { throw 'Creazione issue fallita. HTTP: ' + req.getStatus(); }
            return 'Nuova Issue creata';
        }
    } catch (error) {
        throw 'Failed with error: ' + error;
    }
    """

    # Cerco se il canale esiste già (filtro esatto invece di search)
    media_types = api.mediatype.get(filter={"name": media_name})
    
    # Parametri che Zabbix inietterà nello script JavaScript
    webhook_params = [
        {"name": "url", "value": gitlab_url},
        {"name": "token", "value": gitlab_token},
        {"name": "project_id", "value": gitlab_project_id},
        {"name": "host", "value": "{HOST.NAME}"}, # Aggiunto per il trucco della ricerca per host
        {"name": "title", "value": "{ALERT.SUBJECT}"},
        {"name": "description", "value": "{ALERT.MESSAGE}"},
        {"name": "labels", "value": "zabbix,alert,sygest"}
    ]

    if not media_types:
        print(f"Canale '{media_name}' non trovato. Lo creo in automatico...")
        nuovo_media = api.mediatype.create(
            name=media_name, 
            type=4,  # 4 significa "Webhook"
            status=0, 
            script=js_webhook_script, 
            parameters=webhook_params
        )
        media_id = nuovo_media['mediatypeids'][0]
    else:
        print(f"Canale '{media_name}' trovato. Aggiorno i parametri...")
        media_id = media_types[0]['mediatypeid']
        api.mediatype.update(
            mediatypeid=media_id, 
            status=0, 
            script=js_webhook_script, 
            parameters=webhook_params
        )
    
    # CONFIGURAZIONE DELL'UTENTE
    users = api.user.get(filter={"username": "Admin"})
    # Secondo controllo di sicurezza: verifico che l'utente esista
    if not users:
        print("ERRORE CRITICO: Utente 'Admin' non trovato in Zabbix!")
        return
    # Cerco il gruppo. Se non esiste, lo creo
    target_groups = api.hostgroup.get(filter={"name": "Sygest Targets"})
    if not target_groups:
        nuovo_gruppo = api.hostgroup.create(name="Sygest Targets")
        sygest_group_id = str(nuovo_gruppo['groupids'][0])
    else:
        # Uso str() per forzare il formato a stringa ed evitare l'errore "character string is expected"
        sygest_group_id = str(target_groups[0]['groupid'])

    admin_id = users[0]['userid']
    
    # Preparo le regole di spedizione associando il profilo Admin a GitLab
    user_media = {
        "mediatypeid": media_id, 
        "sendto": ["Zabbix_Sygest_Bot"], # Nei Webhook questo campo spesso fa solo da placeholder
        "active": 0, 
        "severity": 63, # Mandare tutti i livelli di allarme
        "period": "1-7,00:00-24:00"
    }
    
    api.user.update(userid=admin_id, medias=[user_media])


    # CREAZIONE DEL TESTO DELLA ISSUE
    # Questa funzione interna serve per non dover riscrivere a mano la struttura della issue.
    # Ora inietterà semplicemente tutto il Markdown preparato dal nostro script Python!
    def genera_corpo_issue(titolo_header):
        return f"{'{ITEM.VALUE1}'}\n"

    # CREAZIONE DELLE REGOLE ACTIONS
    # Ora diciamo a Zabbix quando deve mandare le mail, dividendo i problemi in 3 categorie di gravità
    
    # --- Categoria INFO E MIGLIORAMENTI ---
    azione_info = "Apri Issue Informativa (GitLab)"
    # Controllo se questa azione esiste già, per evitare di crearne due uguali se lancio lo script due volte
    if not api.action.get(filter={"name": azione_info}):
        corpo_info = genera_corpo_issue("INFO DI SISTEMA - SYGEST")
        
        # Il filtro dice a Zabbix di far scattare questa mail solo se la gravità 
        # (conditiontype: 4) è esattamente uguale (operator: 0) a "Information" (value: 1)
        filtro = {
            "evaltype": 0,
            "conditions": [
                {"conditiontype": 4, "operator": 0, "value": "1"}, 
                {"conditiontype": 0, "operator": 0, "value": sygest_group_id} 
            ]
        }
        
        # preparo l operazione pratica che zabbix dovra eseguire quando scatta il problema
        operazione = {
            # il tipo zero significa "invia un messaggio"
            "operationtype": 0, 
            
            # indico che il destinatario è l amministratore passandogli il suo id esatto
            "opmessage_usr": [{"userid": admin_id}],
            
            # spengo il messaggio preimpostato di zabbix mettendo zero su default_msg
            # in questo modo mi fa usare il mio corpo mail personalizzato e l oggetto che decido io
            # infine gli dico esplicitamente di usare il canale email che ho configurato prima
            "opmessage": {"default_msg": 0, "subject": "{EVENT.NAME}", "message": corpo_info, "mediatypeid": media_id}
        }
        
        # lo status zero serve per accendere la regola immediatamente
        # esc_period definisce la durata degli step di allarme che in questo caso imposto a un ora, non ho impostato altri step ma zabbix mi oblbiga a definire il campo
        # infine gli collego il filtro di gravita e l operazione di invio mail appena scritte
        api.action.create(name=azione_info, eventsource=0, status=0, esc_period="1h", filter=filtro, operations=[operazione])

    # --- Categoria AVVISI MEDI (Patch disponibili) ---
    azione_patch = "Apri Issue Avviso Patch (GitLab)"
    if not api.action.get(filter={"name": azione_patch}):
        corpo_patch = genera_corpo_issue("AVVISO AGGIORNAMENTO - SYGEST")
        
        # Qui il filtro intercetta solo gli eventi di livello 3 (Warning)
        filtro = {
            "evaltype": 0, 
           "conditions": [
                {"conditiontype": 4, "operator": 0, "value": "3"}, 
                {"conditiontype": 0, "operator": 0, "value": sygest_group_id} 
            ]
        }
        
        operazione = {
            "operationtype": 0, 
            "opmessage_usr": [{"userid": admin_id}],
            "opmessage": {"default_msg": 0, "subject": "{EVENT.NAME}", "message": corpo_patch, "mediatypeid": media_id}
        }
        
        api.action.create(name=azione_patch, eventsource=0, status=0, esc_period="1h", filter=filtro, operations=[operazione])


    # --- Categoria PROBLEMI CRITICI (Vulnerabilità gravi o siti non sicuri) ---
    azione_grave = "Apri Issue Critica Sicurezza (GitLab)"
    if not api.action.get(filter={"name": azione_grave}):
        corpo_grave = genera_corpo_issue("ALLARME CRITICO - SYGEST")
        
        # Modifica il filtro in questo modo:
        filtro = {
            "evaltype": 3,  # Custom expression
            "conditions": [
                {"formulaid": "A", "conditiontype": 4, "operator": 0, "value": "4"}, 
                {"formulaid": "B", "conditiontype": 4, "operator": 0, "value": "5"}, 
                {"formulaid": "C", "conditiontype": 0, "operator": 0, "value": sygest_group_id} 
            ],
            "formula": "(A or B) and C"  
        }
        
        operazione = {
            "operationtype": 0, 
            "opmessage_usr": [{"userid": admin_id}],
            "opmessage": {"default_msg": 0, "subject": "{EVENT.NAME}", "message": corpo_grave, "mediatypeid": media_id}
        }
        
        api.action.create(name=azione_grave, eventsource=0, status=0, esc_period="1h", filter=filtro, operations=[operazione])

def sync_hosts(api, db_targets):
    # chiedo a zabbix se esiste già la cartella principale per raggruppare i nostri server
    groups = api.hostgroup.get(filter={"name": "Sygest Targets"})
    
    if groups:
        # se c'è mi salvo il suo numero id
        group_id = groups[0]['groupid']
    else:
        # se non c'è la creo e mi salvo l'id
        nuovo_gruppo = api.hostgroup.create(name="Sygest Targets")
        group_id = nuovo_gruppo['groupids'][0]
        
    # mi scarico dalla memoria di zabbix tutti i server presenti in questo momento
    zabbix_hosts = api.host.get(groupids=group_id, output=["hostid", "host", "status"])
    
    # metto i server di zabbix in un dizionario per trovarli subito dopo quando faro i confronti
    zbx_host_dict = {}
    for h in zabbix_hosts:
        zbx_host_dict[h['host']] = h
        
    db_hostnames = []

    print("Sincronizzo gli host e creo le regole")
    
    # inizio a scorrere uno a uno i server che ho salvato nel mio database mariadb
    for target in db_targets:
        hostname = target['hostname']
        db_hostnames.append(hostname)
        
        try:
            # zabbix ragiona al contrario rispetto al mio database
            # 1 è acceso e 0 è spento mentre per zabbix 0 è monitorato e 1 è disabilitato
            # quindi inverto i numeri per allinearmi alle sue regole
            if target['active']:
                desired_status = 0
            else:
                desired_status = 1
                
            host_id = None

            # controllo se il server del database è una novità o se c'è già su zabbix
            if hostname not in zbx_host_dict:
                # Zabbix è stato programmato per interrogare attivamente i server. Per questo motivo 
                # la sua API ci obbliga sempre a fornire un indirizzo di rete, altrimenti va in errore 
                # e si rifiuta di creare l'host.
                # Visto che nel progetto uso i Trapper (cioè siamo noi che mandiamo i dati a Zabbix), 
                # non serve conoscere l'IP reale della macchina.
                # Per superare questo blocco obbligatorio compiliamo i campi con un'interfaccia default
                interfaccia = {
                    "type": 1,         # 1 significa che stiamo creando un'interfaccia Zabbix Agent
                    "main": 1,         # 1 la imposta come interfaccia principale per questo host
                    "useip": 1,        # Diciamo al sistema di leggere l'IP e di ignorare il DNS
                    "ip": "127.0.0.1", # Uso l'indirizzo base del localhost
                    "dns": "", 
                    "port": "10050"    # Inserisco la porta standard di Zabbix per completare il modulo
                }
                
                # Ora assemblo i pezzi e mando il comando di creazione a Zabbix, passandogli il nome 
                # del server, lo stato di accensione, il gruppo e la nostra interfaccia
                new_host = api.host.create(
                    host=hostname, 
                    status=desired_status, 
                    groups=[{"groupid": group_id}],
                    interfaces=[interfaccia]
                )
                
                # Zabbix crea il server nel suo database e risponde con un pacchetto dati.
                # Da questo pacchetto ricavo l'ID numerico del server appena creato 
                # e me lo salvo nella variabile host_id perché servirà dopo per creare gli item.
                host_id = new_host['hostids'][0]
                
            else:
                # se il server esisteva già controllo se per caso l utente lo ha spento o acceso
                # se lo stato è diverso gli mando il comando per aggiornarlo
                host_id = zbx_host_dict[hostname]['hostid']
                if int(zbx_host_dict[hostname]['status']) != desired_status:
                    api.host.update(hostid=host_id, status=desired_status)

            # Definisco questa funzione interna per creare o modificare gli item su Zabbix.
            # L'ho messa qui dentro così legge in automatico la variabile host_id del ciclo in cui mi trovo
            # e mi evita di scrivere decine di righe di codice ripetitivo per ogni singolo sensore che devo creare.
            def create_or_update_item(name, key_, item_type, val_type, master_id=None, prep=None):
                
                # Interrogo Zabbix per vedere se questo host ha già un item con questa chiave
                existing = api.item.get(filter={"key_": key_}, hostids=host_id)
                
                # Preparo un dizionario con i tre parametri: 
                # il nome visibile, il tipo di item (es. Trapper) e il tipo di dato che riceverà (es. testo o numero)
                params = {
                    "name": name, 
                    "type": item_type, 
                    "value_type": val_type
                }
                
                # Gestisco i parametri opzionali. Se sto creando un "dependent item" aggiungo l'ID dell'item padre.
                # Se ho delle regole di formattazione (come le query JSONPath), aggiungo il blocco preprocessing.
                if master_id is not None: 
                    params["master_itemid"] = master_id
                if prep is not None: 
                    params["preprocessing"] = prep

                # Se il sensore c'è già, prendo il suo ID e mando un comando di update.
                # Se in futuro voglio modificare il nome di un sensore direttamente da questo script, 
                # Zabbix andrà ad aggiornare quello vecchio in automatico senza creare duplicati sulla dashboard.
                if existing:
                    params["itemid"] = existing[0]['itemid']
                    
                    # I due asterischi ** servono per spacchettare il dizionario 'params' e passarlo all'API
                    api.item.update(**params)
                    return existing[0]['itemid']
                
                # Se invece la ricerca iniziale era vuota, significa che è un item nuovo.
                # Aggiungo al pacchetto l'ID dell'host e la chiave univoca per riconoscerlo, poi lo creo da zero.
                else:
                    params["hostid"] = host_id
                    params["key_"] = key_
                    nuovo_item = api.item.create(**params)
                    
                    # Sia che l'abbia aggiornato o creato, alla fine mi faccio sempre restituire il suo ID numerico,
                    # così posso usarlo nel resto del codice per collegarci altri dipendent item o regole di alert
                    return nuovo_item['itemids'][0]

            # Creo i Master Item principali che riceveranno i payload JSON completi dagli script
            # Il parametro type=2 imposta l'item come "Zabbix trapper", mentre value_type=4 lo imposta come tipo di dato "Text"
            i_vuln_id = create_or_update_item("JSON Vuln", "sygest.vuln", 2, 4)
            i_ssl_id = create_or_update_item("JSON SSL", "sygest.ssl_headers", 2, 4)
            
            # CREO L'INTERRUTTORE DI STATO (Riceverà 1 quando python parte e 0 quando finisce)
            # Servirà per fare la scansione a impulsi di Zabbix, evitando controlli infiniti e spam
            create_or_update_item("Scan Status Ping", "sygest.scan_status", 2, 3)
            
            # Funzione interna per creare i Dependent Item collegati ai Master Item definiti sopra.
            # Questi item servono a leggere il JSON ricevuto per isolare le metriche numeriche da usare poi nei grafici e nei trigger.
            def crea_dipendente_numerico(nome, chiave, json_path, master):
                regola = [
                    {
                        # Il type 12 indica a Zabbix di applicare uno step di preprocessing usando JSONPath.
                        "type": 12, 
                        
                        # Gli passo la variabile json_path con le coordinate esatte. È il percorso che Zabbix deve seguire tra le parentesi graffe
                        "params": json_path, 
                        
                        # Imposto lo zero per dirgli di usare la gestione degli errori di default. 
                        # Se il campo che cerco non esiste nel JSON, Zabbix smette di leggere e mi segnala l'errore sulla dashboard.
                        "error_handler": 0, 
                        
                        # Siccome ho scelto il comportamento standard, non mi serve dargli 
                        # nessuna istruzione di riserva o valore di fallback, quindi lascio il campo vuoto.
                        "error_handler_params": ""
                    }
                ]
                # Richiamo la funzione di base passando type=18 per creare formalmente un "Dependent item" 
                # e value_type=3 per indicare che il valore estratto sarà di tipo "Numeric (unsigned)"
                return create_or_update_item(nome, chiave, 18, 3, master, regola)
                
            # Definisco un'altra funzione interna che serve per estrarre blocchi di testo lunghi come i messaggi pre-formattati per gli allarmi 
            def crea_dipendente_testo(nome, chiave, json_path, master):
                # Preparo la regola di Preprocessing. Come prima, uso il type=12 per dire a Zabbix 
                # di usare la query JSONPath e ritagliare la stringa esatta dentro il payload JSON.
                regola = [
                    {
                        "type": 12, 
                        "params": json_path, 
                        "error_handler": 0, 
                        "error_handler_params": ""
                    }
                ]
                
                # Richiamo la funzione principale per creare il Dependent Item (type=18) e agganciarlo al Master Item.
                # Il parametro value_type=4, che in Zabbix significa "Text" e permette al database di salvare stringhe molto lunghe
                return create_or_update_item(nome, chiave, 18, 4, master, regola)
                
            # Creo Dependent Item numerici che si agganciano al Master Item TRIVY
            # Ognuno di questi item usa una query JSONPath specifica per estrarre un singolo contatore 
            # dal payload JSON inviato da Trivy, ignorando tutto il resto del file.

            # Estraggo il flag (0 o 1) che mi dice se questa è la prima scansione fatta su questo host
            crea_dipendente_numerico(
                "Vuln First Read Flag", 
                "vuln.is_first_read", 
                "$.metrics.is_first_read", 
                i_vuln_id
            )

            # Estraggo il numero totale delle vulnerabilità attualmente attive e presenti sul server
            crea_dipendente_numerico(
                "Vuln Totale CVE attivi", 
                "vuln.total_active", 
                "$.metrics.total_active", 
                i_vuln_id
            )

            # Estraggo il conteggio delle vulnerabilità per cui esiste già un aggiornamento software (Patch) pronto da installare
            crea_dipendente_numerico(
                "Vuln Totale CVE CON Patch", 
                "vuln.total_with_patch", 
                "$.metrics.total_with_patch", 
                i_vuln_id
            )

            # Estraggo il conteggio delle vulnerabilità più fastidiose, quelle per cui i produttori non hanno ancora rilasciato soluzioni
            crea_dipendente_numerico(
                "Vuln Totale CVE SENZA Patch", 
                "vuln.total_without_patch", 
                "$.metrics.total_without_patch", 
                i_vuln_id
            )

            # Estraggo il numero dei soli CVE appena scoperti nell'ultima scansione e che possono essere già sistemati
            crea_dipendente_numerico(
                "Vuln NUOVI CVE CON Patch", 
                "vuln.new_with_patch_count", 
                "$.metrics.new_with_patch_count", 
                i_vuln_id
            )

            # Estraggo il numero dei soli CVE appena scoperti nell'ultima scansione che purtroppo non hanno ancora una patch
            crea_dipendente_numerico(
                "Vuln NUOVI CVE SENZA Patch", 
                "vuln.new_without_patch_count", 
                "$.metrics.new_without_patch_count", 
                i_vuln_id
            )

            # Creo i Dependent Item di tipo testo agganciati al Master Item delle vulnerabilità (i_vuln_id).
            # Tramite JSONPath estraggo le stringhe già pre-formattate dal mio script Python, così Zabbix dovrà
            # semplicemente prenderle e scriverle dentro le mail di alert senza dover fare ulteriori elaborazioni.
            
            # Estraggo il blocco di testo che riassume i risultati della prima scansione del server
            crea_dipendente_testo(
                "Vuln Testo Prima Lettura", 
                "vuln.first_read_text", 
                "$.texts.first_read_text", 
                i_vuln_id
            )
            
            # Estraggo il blocco di testo che elenca i dettagli delle nuove vulnerabilità che hanno già una patch disponibile.
            crea_dipendente_testo(
                "Vuln Testo Nuovi CON Patch", 
                "vuln.new_with_patch_text", 
                "$.texts.new_with_patch_text", 
                i_vuln_id
            )
            
            # Estraggo il blocco di testo critico con l'elenco delle vulnerabilità scoperte ma senza ancora una patch.
            crea_dipendente_testo(
                "Vuln Testo Nuovi SENZA Patch", 
                "vuln.new_without_patch_text", 
                "$.texts.new_without_patch_text", 
                i_vuln_id
            )

            # Passo ai controlli di sicurezza web e creo i Dependent Item agganciandoli al secondo Master Item (i_ssl_id).
            # Questo Master Item riceve il payload JSON specifico per i certificati SSL e gli HTTP Header.
            
            # Estraggo il punteggio numerico della sicurezza web per poter disegnare i grafici su Zabbix
            crea_dipendente_numerico(
                "Sicurezza Web Score", 
                "headers.score", 
                "$.score", 
                i_ssl_id
            )
            
            # Estraggo il voto in lettere (A, B, C, ecc.) per mostrarlo in modo facile sulla dashboard
            crea_dipendente_testo(
                "Sicurezza Web Grade Headers", 
                "headers.grade", 
                "$.headers_grade", 
                i_ssl_id
            )
            
            # Estraggo il voto in lettere del certificato SSL generato da testssl.sh
            crea_dipendente_testo(
                "Sicurezza Web Grade SSL", 
                "ssl.grade", 
                "$.ssl_grade", 
                i_ssl_id
            )
            
            # Estraggo come valore numerico i giorni rimanenti prima che il certificato SSL del sito scada
            crea_dipendente_numerico(
                "SSL Giorni scadenza CA", 
                "ssl.days_left", 
                "$.days_left", 
                i_ssl_id
            )
            
            # Estraggo come stringa di testo l'impronta digitale (Thumbprint) del certificato
            crea_dipendente_testo(
                "SSL Thumbprint", 
                "ssl.thumbprint", 
                "$.thumbprint", 
                i_ssl_id
            )
            
            # Estraggo l'elenco testuale di vulnerabilità e warning estrapolati da Python
            crea_dipendente_testo(
                "Sicurezza Web Warnings", 
                "headers.warnings_text", 
                "$.warnings_text", 
                i_ssl_id
            )
            
            # Estraggo l'INTERO report Markdown. Questo è l'Item più importante perché è quello 
            # che verrà inviato a GitLab per compilare il corpo della Issue.
            crea_dipendente_testo(
                "Sicurezza Web Full Report Markdown", 
                "headers.full_report", 
                "$.full_markdown_report", 
                i_ssl_id
            )

            # Definisco un'altra funzione interna, per gestire la creazione dei Trigger.
            # Riceve in ingresso il nome del trigger (desc), l'espressione logica/matematica per farlo scattare (expr) 
            # e il livello di gravità dell'evento (prio).
            def create_or_update_trigger(desc, expr, prio):
                
                # Interrogo l'API per verificare se su questo specifico host esiste già un Trigger con lo stesso nome.
                existing = api.trigger.get(filter={"description": desc}, hostids=host_id)
                
                # Se il Trigger esiste già, provo ad aggiornarlo andando a sovrascrivere l'espressione e la priorità.
                if existing:
                    try: 
                        api.trigger.update(
                            triggerid=existing[0]['triggerid'], 
                            expression=expr, 
                            priority=prio
                        )
                    # Inserisco tutto in un blocco try-except perché L'API di Zabbix va in crash se riceve 
                    # una richiesta di update con dei parametri che sono identici a quelli che ha già 
                    except Exception: 
                        pass 
                
                # Se il controllo non trova nulla creo il Trigger partendo da zero
                else:
                    api.trigger.create(description=desc, expression=expr, priority=prio)

            # CREAZIONE DEI TRIGGER
            # Uso la funzione appena definita per inserire le regole matematiche che faranno scattare gli alert.
            # Per ogni Trigger passo 3 parametri: il nome (con la macro {HOST.NAME} che Zabbix compila da solo), 
            # l'espressione e il livello di Severity (da 1 a 5).
            
            # --- TRIGGER VULNERABILITÀ TRIVY ---
            
            # Livello 1 (Information)
            # L'espressione controlla due cose con la funzione 'last': che il testo della mail non sia vuoto (length>0) 
            # e che il flag numerico 'is_first_read' sia uguale a 1.
            # NOTA BENE: l'item di testo è sempre il primo nell'espressione così {ITEM.VALUE1} stampa il markdown!
            create_or_update_trigger(
                f"Info Prima lettura massiva Trivy completata su {{HOST.NAME}}", 
                f"length(last(/{hostname}/vuln.first_read_text))>0 and last(/{hostname}/vuln.is_first_read)=1", 
                1 
            )

            # Livello 5 (Disaster)
            # Scatta se Trivy trova vulnerabilità nuove. Verifico che ci sia il testo per la mail e che il contatore dei nuovi CVE senza di patch sia maggiore di zero.
            create_or_update_trigger(
                f"CRITICO Rilevati Nuovi CVE SENZA PATCH su {{HOST.NAME}}", 
                f"length(last(/{hostname}/vuln.new_without_patch_text))>0 and last(/{hostname}/vuln.new_without_patch_count)>0", 
                5 
            )

            # Livello 3 (Warning)
            # Ci sono vulnerabilità nuove, ma i produttori hanno già la patch.
            create_or_update_trigger(
                f"Avviso Rilevati Nuovi CVE o nuove patch disponibili su {{HOST.NAME}}", 
                f"length(last(/{hostname}/vuln.new_with_patch_text))>0 and last(/{hostname}/vuln.new_with_patch_count)>0", 
                3 
            )

            # --- TRIGGER SICUREZZA WEB E HEADERS (Logica ad Impulsi per non spammare) ---          
            
            # 1. Prima scansione in assoluto (Livello 1 - Information)
            # Mettendo "headers.full_report" al primo posto, Zabbix assegnerà il Markdown alla variabile {ITEM.VALUE1} 
            create_or_update_trigger(
                f"Report su {{HOST.NAME}}", 
                f"length(last(/{hostname}/headers.full_report))>0 and last(/{hostname}/sygest.scan_status)=1 and count(/{hostname}/headers.score,#2)=1", 
                1
            )

            # 2. Peggioramento (Livello 4 - High)
            create_or_update_trigger(
                f"Peggioramento su {{HOST.NAME}}", 
                f"length(last(/{hostname}/headers.full_report))>0 and last(/{hostname}/sygest.scan_status)=1 and last(/{hostname}/headers.score)<last(/{hostname}/headers.score,#2) and count(/{hostname}/headers.score,#2)>=2", 
                4
            )

            # 3. Miglioramento (Livello 1 - Information)
            create_or_update_trigger(
                f"Miglioramento su {{HOST.NAME}}", 
                f"length(last(/{hostname}/headers.full_report))>0 and last(/{hostname}/sygest.scan_status)=1 and last(/{hostname}/headers.score)>last(/{hostname}/headers.score,#2) and count(/{hostname}/headers.score,#2)>=2", 
                1
            )

            # 4. Sincronizzazione di Routine (Livello 1 - Information)
            # Questo è il Trigger intelligente! Scatta quando Python finisce la scansione e vede che NON ci sono stati cambiamenti.
            create_or_update_trigger(
                f"Routine Sync su {{HOST.NAME}}", 
                f"length(last(/{hostname}/headers.full_report))>0 and last(/{hostname}/sygest.scan_status)=1 and last(/{hostname}/headers.score)=last(/{hostname}/headers.score,#2) and count(/{hostname}/headers.score,#2)>=2", 
                1
            )

            # --- TRIGGER CERTIFICATI SSL ---      
            # Livello 4 (High)
            create_or_update_trigger(f"Allarme Certificato SSL in scadenza per {{HOST.NAME}}", f"length(last(/{hostname}/headers.full_report))>0 and last(/{hostname}/sygest.scan_status)=1 and last(/{hostname}/ssl.days_left)<30 and last(/{hostname}/ssl.days_left)>=0", 4)
            
            # Livello 1 (Information)
            create_or_update_trigger(f"Info Thumbprint SSL cambiato per {{HOST.NAME}}", f"length(last(/{hostname}/headers.full_report))>0 and last(/{hostname}/sygest.scan_status)=1 and last(/{hostname}/ssl.thumbprint)<>last(/{hostname}/ssl.thumbprint,#2) and length(last(/{hostname}/ssl.thumbprint))>5", 1)

        except Exception as e:
            # Stampo a video l'eccezione (e) per capire il problema e uso il comando 'continue' 
            # per dire al ciclo di non fermarsi e passare a configurare il prossimo server della lista
            print(f"Ho riscontrato un errore durante l allineamento del server {hostname} con eccezione {e}")
            continue

    # Prendo il dizionario (zbx_host_dict) che avevo riempito all'inizio dello script 
    # e che contiene tutti i server attualmente presenti su Zabbix. Li scorro uno per uno.
    for zbx_hostname, zbx_data in zbx_host_dict.items():
        
        # Faccio una fase di pulizia dove elimino da zabbix gli host che sono presenti solo nel DB di zabbix ma non nel mio
        if zbx_hostname not in db_hostnames:
            try:
                # Zabbix lo eliminerà definitivamente con tutti gli Item, i Trigger dipendenti e lo storico dei dati associati.
                api.host.delete(zbx_data['hostid'])
                
            except Exception as e:
                pass

def main():
    connection = None
    zapi = None
    try:
        # Mi collego al mio database MariaDB spacchettando il dizionario di configurazione (DB_CONFIG) con i due asterischi (**).
        connection = pymysql.connect(**DB_CONFIG)
        
        # Ricavo tutti i server sul DB, prendendo ID, nome e status
        with connection.cursor() as cursor:
            cursor.execute("SELECT id, hostname, active FROM targets")
            
            # Salvo tutto il blocco di risultati dentro la variabile db_targets.
            db_targets = cursor.fetchall()

        print("\nAVVIO PROCEDURA DI SINCRONIZZAZIONE ZABBIX E GITLAB")
        
        # Inizializzo la connessione passando l'URL e faccio il login per ottenere il token di sessione.
        zapi = ZabbixAPI(url=ZABBIX_URL)
        zapi.login(user=ZABBIX_USER, password=ZABBIX_PASSWORD)
                
        # Chiamo la funzione per configurare il server SMTP, le email e le regole generali di notifica.
        configure_zabbix_alerts(zapi)
        
        # Passo l'api di Zabbix e la lista dei server estratti dal mio DB (db_targets) 
        sync_hosts(zapi, db_targets)
        
        print("Allineamento Zabbix terminato con successo")

    except Exception as e:
        print(f"\nC'è stato un errore nella sincronizzazione generale: {e}")
        
    finally:
        # Libero risorse chiudendo la connessione SQL
        if connection: 
            connection.close()
            
        # Faccio lo stesso con zabbix
        if zapi: 
            zapi.logout()

if __name__ == "__main__":
    main()