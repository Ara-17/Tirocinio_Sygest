from flask import Flask, request, jsonify
from flasgger import Swagger
import pymysql
import json
from zabbix_utils import Sender, ItemValue

# Inizializzo l'app Flask che farà da server in ascolto per ricevere i dati
app = Flask(__name__)

# Attivo Swagger per generare l'interfaccia grafica in automatico. Crea una pagina web dove posso testare e documentare l'API 
swagger = Swagger(app, template={
    "info": {
        "title": "API Sygest",
        "description": "Ricezione passiva dei dati di sicurezza e vulnerability management",
        "version": "1.0.0"
    }
})

# Preparo i parametri per collegarmi al database MariaDB
DB_CONFIG = {
    'host': 'sygest-db',
    'user': 'root',
    'password': 'root_pwd_sygest',
    'database': 'progetto_sygest',
    'charset': 'utf8mb4',
    # Chiedo a pymysql di restituirmi i risultati delle query come dizionari 
    'cursorclass': pymysql.cursors.DictCursor
}

ZABBIX_SERVER = 'zabbix-server'
ZABBIX_PORT = 10051

# Creo l'endpoint che aspetterà i dati inviati dai server
@app.route('/api/v1/trivy', methods=['POST'])
def receive_trivy_report():
    """
    Ricezione del report generato da Aqua Trivy.
    Questo blocco riceve il file JSON e lo confronta con lo storico del nostro database.
    ---
    tags:
      - Vulnerability Management
    consumes:
      - multipart/form-data
    parameters:
      - name: hostname
        in: formData
        type: string
        required: true
        description: Il nome del server target scansionato
      - name: file
        in: formData
        type: file
        required: true
        description: Il file JSON generato in locale da Trivy
    responses:
      200:
        description: File ricevuto, processato e inviato a Zabbix senza problemi
      400:
        description: Mancano dei parametri obbligatori nella richiesta
      404:
        description: Il server non è registrato nel nostro database
      500:
        description: Errore interno del server o del database
    """
    
    # Prendo il nome del server (hostname) dalla richiesta web.
    hostname = request.form.get('hostname')
    
    # Se chi ha lanciato lo script non mi ha passato il nome del server, blocco la richiesta e restituisco un errore 400.
    if not hostname:
        return jsonify({"status": "error", "message": "Manca il parametro hostname"}), 400
        
    # Faccio un controllo simile sul file verificando che la chiave 'file' esista nella richiesta.
    if 'file' not in request.files:
        return jsonify({"status": "error", "message": "Manca il file JSON"}), 400
        
    file = request.files['file']
    
    # Controllo che il file caricato abbia effettivamente un nome (e quindi non sia vuoto o corrotto).
    if file.filename == '':
        return jsonify({"status": "error", "message": "Il file caricato risulta vuoto"}), 400

    try:
        # Uso la libreria json per convertire il file in arrivo in un dizionario Python.
        trivy_data = json.load(file)
        
        # Creo un dizionario temporaneo dove andrò a salvare solo le vulnerabilità estratte da questa scansione,
        # ignorando altre informazioni che Trivy metterà nel report
        scanned_cves = {}
        
        # Inizio a navigare la struttura del JSON
        for result in trivy_data.get('Results', []):
            for vuln in result.get('Vulnerabilities', []):
                cve_id = vuln.get('VulnerabilityID', 'Sconosciuto')
                software = vuln.get('PkgName', 'Sconosciuto')
                
                # Cerco il link ufficiale per scaricare l'aggiornamento
                link_patch = vuln.get('PrimaryURL')
                
                # Se Trivy non mi ha fornito il link principale, provo a controllare la lista dei link 
                # di "reference". Se non c'è neanche lì, inserisco "Non disponibile".
                if not link_patch:
                    refs = vuln.get('References', [])
                    if refs:
                        link_patch = refs[0]
                    else:
                        link_patch = "Non disponibile"
                
                # Uso una "tupla" come chiave doppia (ID vulnerabilità + Nome Software).
                # Questo perché la stessa vulnerabilità potrebbe colpire due programmi 
                # diversi installati sulla stessa macchina.
                key = (cve_id, software)
                
                scanned_cves[key] = {
                    "current_version": vuln.get('InstalledVersion', 'Sconosciuta'),
                    "fixed_version": vuln.get('FixedVersion', ''),
                    "severity": vuln.get('Severity', 'UNKNOWN'),
                    "description": vuln.get('Description', 'Nessuna descrizione presente'),
                    "link_patch": link_patch
                }

        # Mi collego al database usando le configurazioni preparate all'inizio.
        connection = pymysql.connect(**DB_CONFIG)
        with connection.cursor() as cursor:
            
            # Cerco l'hostname nel database. Se il server non è presente, rifiuto i dati. 
            cursor.execute("SELECT id FROM targets WHERE hostname = %s", (hostname,))
            target = cursor.fetchone()
            
            if not target:
                return jsonify({"status": "error", "message": "Questo host non esiste nel database"}), 404
                
            target_id = target['id']

            # Mi salvo lo storico delle vulnerabilità già note per questo specifico server sul mio DB
            # Serve per poter fare il confronto e capire se ci sono problemi nuovi
            cursor.execute("SELECT cve_id, software, fixed_version FROM vulnerabilities WHERE target_id = %s", (target_id,))
            db_records = cursor.fetchall()
            
            # Salvo lo storico del DB in un dizionario
            db_cves = {}
            for row in db_records:
                chiave_db = (row['cve_id'], row['software'])
                db_cves[chiave_db] = row
            
            # Se lo storico del DB è vuoto, significa che è la prima scansione per quell'host
            is_first_read = len(db_cves) == 0

            # Preparo le liste di testo che faranno da "corpo" alle email inviate da Zabbix.
            new_with_patch_list = []
            new_no_patch_list = []
            all_with_patch_list = []
            all_no_patch_list = []
            
            # Inizio a confrontare i dati nuovi (scanned_cves) con quelli già presenti nel DB (db_cves).
            for key, data in scanned_cves.items():
                cve_id = key[0]
                software = key[1]
                
                # Controllo per sapere se esiste un aggiornamento software risolutivo
                if data['fixed_version']:
                    has_patch = True
                else:
                    has_patch = False
                
                # Formatto il testo per il singolo alert
                text_block = f"[{cve_id}] {software} v{data['current_version']}\n"
                
                if has_patch:
                    text_block += f"Gravità {data['severity']} | Patch {data['fixed_version']}\n"
                else:
                    text_block += f"Gravità {data['severity']} | Patch NESSUNA\n"
                    
                text_block += f"Link {data['link_patch']}\n"
                text_block += f"Info {data['description'][:150]}...\n\n"

                # Inserisco il blocco di testo nel conteggio totale per tenere traccia dello stato attuale del server
                if has_patch:
                    all_with_patch_list.append(text_block)
                else:
                    all_no_patch_list.append(text_block)

                # Controllo se questo specifico problema è nuovo per il DB
                if key not in db_cves:
                    
                    # Lo salvo nel DB
                    cursor.execute("""
                        INSERT INTO vulnerabilities (target_id, cve_id, software, current_version, fixed_version, severity, description, link_patch)
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                    """, (target_id, cve_id, software, data['current_version'], data['fixed_version'], data['severity'], data['description'], data['link_patch']))
                    
                    # Se non è la prima scansione del server, metto il testo tra le nuove letture
                    # per far scattare l'alert di Zabbix.
                    if not is_first_read:
                        if has_patch:
                            new_with_patch_list.append(text_block)
                        else:
                            new_no_patch_list.append(text_block)
                        
                else:
                    # Se il problema esisteva già, aggiorno la colonna 'last_seen' con la data di oggi 
                    # per confermare che la vulnerabilità è ancora lì e non è stata sistemata.
                    cursor.execute("UPDATE vulnerabilities SET last_seen = NOW() WHERE target_id = %s AND cve_id = %s AND software = %s", (target_id, cve_id, software))
                    
                    # Controllo se per questa specifica vulnerabilità avevamo già una patch disponibile
                    vecchia_patch = db_cves[key]['fixed_version']
                    
                    # Se questa condizione è verificata vuol dire che i produttori del software hanno rilasciato l'aggiornamento risolutivo
                    if has_patch and not vecchia_patch:
                        
                        # Aggiorno il database inserendo il numero della nuova versione sicura.
                        cursor.execute("UPDATE vulnerabilities SET fixed_version = %s WHERE target_id = %s AND cve_id = %s AND software = %s", (data['fixed_version'], target_id, cve_id, software))
                        
                        # Se non mi trovo nella prima scansione prendo il testo di questo allarme e lo inserisco nella lista dei "nuovi problemi con patch"
                        # In questo modo Zabbix manderà una mail per avvisare che quel CVE ha un aggiornamento risolutivo
                        if not is_first_read:
                            new_with_patch_list.append(text_block)

            # Cerco nel database i vecchi problemi che lo scanner nella nuova analisi non ha trovato.
            # Questo significa è stato aggiornato il server, quindi posso cancellare dal DB i CVE risolti
            for key in db_cves:
                if key not in scanned_cves:
                    cursor.execute("DELETE FROM vulnerabilities WHERE target_id = %s AND cve_id = %s AND software = %s", (target_id, key[0], key[1]))

            # Salvo le modifiche sul database
            connection.commit()

            # Una volta finito il confronto dei dati, assemblo i messaggi di testo finali
            # Unisco le varie liste di vulnerabilità create in precedenza per formare delle stringhe uniche
            # che Zabbix userà come corpo delle email.
            
            first_read_msg = ""
            # Se è la prima scansione in assoluto, preparo un messaggio di riepilogo generale
            # che indica semplicemente quante vulnerabilità totali abbiamo trovato sul server.
            if is_first_read:
                totale_cve_trovati = len(all_with_patch_list) + len(all_no_patch_list)
                first_read_msg = f"Scansione per {hostname} completata e trovati {totale_cve_trovati} CVE totali"

            new_with_patch_msg = ""
            # Se ci sono nuovi CVE con patch disponibile, creo il blocco di testo dedicato.
            # Uso il comando "".join() per incollare insieme tutti i singoli blocchi di testo delle vulnerabilità.
            if new_with_patch_list:
                new_with_patch_msg = "NUOVE VULNERABILITÀ O PATCH DISPONIBILI\n========================================\n" + "".join(new_with_patch_list)

            new_no_patch_msg = ""
            # Faccio lo stesso per i nuovi CVE critici senza patch
            if new_no_patch_list:
                new_no_patch_msg = "ALLARME NUOVE VULNERABILITÀ SENZA PATCH\n========================================\n" + "".join(new_no_patch_list)

            # Preparo i contatori numerici 
            # Imposto i contatori dei NUOVI problemi a zero perché altrimenti, al primo avvio, Zabbix 
            # vedrebbe centinaia di CVE tutti insieme e farebbe scattare troppi alert
            count_new_with_patch = len(new_with_patch_list) if not is_first_read else 0
            count_new_no_patch = len(new_no_patch_list) if not is_first_read else 0

            # Costruisco l'oggetto report che sarà un dizionario Python che rispecchia esattamente 
            # la struttura JSON che ho configurato su Zabbix nei Master Item.
            # Divido tra 'metrics' e 'texts'
            report = {
                "metrics": {
                    "is_first_read": 1 if is_first_read else 0,
                    "total_active": len(all_with_patch_list) + len(all_no_patch_list),
                    "total_with_patch": len(all_with_patch_list),
                    "total_without_patch": len(all_no_patch_list),
                    "new_with_patch_count": count_new_with_patch,
                    "new_without_patch_count": count_new_no_patch
                },
                "texts": {
                    "first_read_text": first_read_msg,
                    "new_with_patch_text": new_with_patch_msg,
                    "new_without_patch_text": new_no_patch_msg,
                    "active_with_patch_list": "".join(all_with_patch_list),
                    "active_without_patch_list": "".join(all_no_patch_list)
                }
            }

            # Configuro il 'Sender', ovvero il componente che si occupa di inviare al server Zabbix.
            sender = Sender(server=ZABBIX_SERVER, port=ZABBIX_PORT)
            
            # Questa è la riga in cui creo il pacchetto da spedire.
            # Uso la classe ItemValue per mettere insieme tre informazioni fondamentali:
            # l'hostname che dice a Zabbix il nome esatto del server a cui appartengono i dati
            # il sygest.vuln'che indica la chiave dell'item dove Zabbix deve salvare il file
            # il json.dumps(report) che trasforma il dizionario Python in una stringa JSON            
            packet = [ItemValue(hostname, 'sygest.vuln', json.dumps(report))]            

            sender.send(packet)
            
            print(f"Elaborazione terminata per {hostname} e dati mandati a Zabbix")

        # Rispondo alla chiamata con 200 (Success)
        return jsonify({"status": "success", "message": "Dati elaborati e inviati correttamente"}), 200

    except Exception as e:
        print(f"Errore durante l'elaborazione del report: {e}")
        return jsonify({"status": "error", "message": str(e)}), 500
        
    finally:
        if 'connection' in locals() and connection:
            connection.close()

# Avvio il server Flask e lo metto in ascolto su tutte le interfacce di rete (0.0.0.0) alla porta 5000.
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)