from flask import Flask, request, jsonify
import pymysql
import json
from zabbix_utils import Sender, ItemValue

app = Flask(__name__)

# Imposto i parametri per collegarmi al database locale
DB_CONFIG = {
    'host': 'sygest-db',
    'user': 'root',
    'password': 'root_pwd_sygest',
    'database': 'progetto_sygest',
    'charset': 'utf8mb4',
    # Chiedo a pymysql di restituirmi i risultati sotto forma di dizionario
    'cursorclass': pymysql.cursors.DictCursor
}

ZABBIX_SERVER = 'zabbix-server'
ZABBIX_PORT = 10051

# Definisco la rotta per ricevere i dati passati dal comando curl del server Windows
@app.route('/api/v1/trivy', methods=['POST'])
def receive_trivy_report():
    
    # Estraggo il nome del server dalla richiesta
    hostname = request.form.get('hostname')
    
    # Blocco l esecuzione se mancano dei parametri fondamentali
    if not hostname:
        return jsonify({"status": "error", "message": "Manca il parametro hostname"}), 400
        
    if 'file' not in request.files:
        return jsonify({"status": "error", "message": "Manca il file JSON allegato"}), 400
        
    file = request.files['file']
    
    if file.filename == '':
        return jsonify({"status": "error", "message": "Il file caricato risulta vuoto"}), 400

    try:
        # Leggo il contenuto del file JSON inviato da Trivy
        trivy_data = json.load(file)
        
        # Creo un dizionario per salvare tutte le vulnerabilita trovate nella scansione attuale
        scanned_cves = {}
        
        for result in trivy_data.get('Results', []):
            for vuln in result.get('Vulnerabilities', []):
                cve_id = vuln.get('VulnerabilityID', 'Sconosciuto')
                software = vuln.get('PkgName', 'Sconosciuto')
                
                # Cerco il link per scaricare la patch
                link_patch = vuln.get('PrimaryURL')
                
                # Se il link principale manca vado a pescarlo dalla lista delle reference
                if not link_patch:
                    refs = vuln.get('References', [])
                    if refs:
                        link_patch = refs[0]
                    else:
                        link_patch = "Non disponibile"
                
                # Uso una chiave multipla perche lo stesso CVE puo colpire piu programmi diversi nello stesso server
                key = (cve_id, software)
                
                scanned_cves[key] = {
                    "current_version": vuln.get('InstalledVersion', 'Sconosciuta'),
                    "fixed_version": vuln.get('FixedVersion', ''),
                    "severity": vuln.get('Severity', 'UNKNOWN'),
                    "description": vuln.get('Description', 'Nessuna descrizione presente'),
                    "link_patch": link_patch
                }

        connection = pymysql.connect(**DB_CONFIG)
        with connection.cursor() as cursor:
            # Cerco l id del target nel database usando il nome del server
            cursor.execute("SELECT id FROM targets WHERE hostname = %s", (hostname,))
            target = cursor.fetchone()
            
            # Se l host non esiste nel DB rifiuto i dati per non creare sporcizia nel database
            if not target:
                return jsonify({"status": "error", "message": "Questo host non esiste nel DB"}), 404
                
            target_id = target['id']

            # Recupero lo storico delle vulnerabilita gia note per questo server
            cursor.execute("SELECT cve_id, software, fixed_version FROM vulnerabilities WHERE target_id = %s", (target_id,))
            db_records = cursor.fetchall()
            
            # Trasformo la lista in un dizionario per fare i controlli piu velocemente
            db_cves = {}
            for row in db_records:
                chiave_db = (row['cve_id'], row['software'])
                db_cves[chiave_db] = row
            
            # Se il database e vuoto significa che e la primissima scansione in assoluto su questo host
            is_first_read = len(db_cves) == 0

            # Preparo le liste per smistare i testi da mandare poi a Zabbix nelle mail
            new_with_patch_list = []
            new_no_patch_list = []
            all_with_patch_list = []
            all_no_patch_list = []
            
            # Inizio a confrontare i dati appena arrivati da Trivy con quelli che ho gia nel database
            for key, data in scanned_cves.items():
                cve_id = key[0]
                software = key[1]
                
                # Verifico se la patch esiste
                if data['fixed_version']:
                    has_patch = True
                else:
                    has_patch = False
                
                # Formatto il blocco di testo per la singola vulnerabilita
                text_block = f"[{cve_id}] {software} v{data['current_version']}\n"
                
                if has_patch:
                    text_block += f"Gravita {data['severity']} | Patch {data['fixed_version']}\n"
                else:
                    text_block += f"Gravita {data['severity']} | Patch NESSUNA\n"
                    
                text_block += f"Link {data['link_patch']}\n"
                text_block += f"Info {data['description'][:150]}...\n\n"

                # Aggiungo il testo alle liste globali per lo storico completo
                if has_patch:
                    all_with_patch_list.append(text_block)
                else:
                    all_no_patch_list.append(text_block)

                # Verifico se il CVE appena letto e nuovo o era gia presente nel database
                if key not in db_cves:
                    # Inserisco la nuova falla nel DB locale
                    cursor.execute("""
                        INSERT INTO vulnerabilities (target_id, cve_id, software, current_version, fixed_version, severity, description, link_patch)
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                    """, (target_id, cve_id, software, data['current_version'], data['fixed_version'], data['severity'], data['description'], data['link_patch']))
                    
                    # Se non e la prima lettura aggiungo il testo agli alert per far scattare Zabbix
                    if not is_first_read:
                        if has_patch:
                            new_with_patch_list.append(text_block)
                        else:
                            new_no_patch_list.append(text_block)
                        
                else:
                    # Aggiorno la data di ultima rilevazione per capire che il problema non e stato risolto
                    cursor.execute("UPDATE vulnerabilities SET last_seen = NOW() WHERE target_id = %s AND cve_id = %s AND software = %s", (target_id, cve_id, software))
                    
                    # Controllo se per caso e uscita una patch che prima non era disponibile
                    vecchia_patch = db_cves[key]['fixed_version']
                    
                    if has_patch and not vecchia_patch:
                        cursor.execute("UPDATE vulnerabilities SET fixed_version = %s WHERE target_id = %s AND cve_id = %s AND software = %s", (data['fixed_version'], target_id, cve_id, software))
                        
                        # Lo metto nella lista dei nuovi CVE per fare arrivare la notifica di aggiornamento
                        if not is_first_read:
                            new_with_patch_list.append(text_block)

            # Eseguo il Garbage Collector
            # Elimino dal database tutti i CVE che lo scanner non ha piu trovato nella macchina
            for key in db_cves:
                if key not in scanned_cves:
                    cursor.execute("DELETE FROM vulnerabilities WHERE target_id = %s AND cve_id = %s AND software = %s", (target_id, key[0], key[1]))

            # Salvo definitivamente tutte le modifiche fatte alle tabelle
            connection.commit()

            # Preparo i messaggi finali da spedire ai Trigger
            first_read_msg = ""
            if is_first_read:
                totale_cve_trovati = len(all_with_patch_list) + len(all_no_patch_list)
                first_read_msg = f"Scansione per {hostname}, sono stati rilevati un totale di {totale_cve_trovati} CVE attivi sul sistema"

            new_with_patch_msg = ""
            if new_with_patch_list:
                new_with_patch_msg = "NUOVE VULNERABILITA O PATCH DISPONIBILI\n========================================\n" + "".join(new_with_patch_list)

            new_no_patch_msg = ""
            if new_no_patch_list:
                new_no_patch_msg = "ALLARME - NUOVE VULNERABILITA SENZA PATCH\n========================================\n" + "".join(new_no_patch_list)

            # Calcolo i contatori per Zabbix solo se non e la prima scansione
            count_new_with_patch = len(new_with_patch_list) if not is_first_read else 0
            count_new_no_patch = len(new_no_patch_list) if not is_first_read else 0

            # Creo la struttura del payload JSON rispettando i nomi stabiliti nello Swagger
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

            # Converto in pacchetto e spedisco tutto al Trapper
            sender = Sender(server=ZABBIX_SERVER, port=ZABBIX_PORT)
            packet = [ItemValue(hostname, 'sygest.vuln', json.dumps(report))]
            sender.send(packet)
            
            print(f"Elaborazione terminata per {hostname} e dati mandati a Zabbix in sicurezza")

        return jsonify({"status": "success", "message": "Tutto inviato correttamente"}), 200

    except Exception as e:
        # Se qualcosa esplode catturo l errore e lo restituisco a chi ha lanciato il curl
        print(f"Errore nello spacchettamento o salvataggio {e}")
        return jsonify({"status": "error", "message": str(e)}), 500
        
    finally:
        # Mi assicuro sempre di chiudere il database per non lasciare sessioni appese
        if 'connection' in locals() and connection:
            connection.close()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)