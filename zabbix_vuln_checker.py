import subprocess
import os
import re
import pymysql
import requests
import xml.etree.ElementTree as ET
import time
import shutil
import json
from zabbix_utils import Sender, ItemValue

# --- CONFIGURAZIONE ---
# Questa API Key permette al mio script di fare un numero molto più elevato di richieste 
# senza essere bloccato
API_KEY_NVD = "0fb4b560-3f2a-4e38-a330-15371cc7639c"

DB_CONFIG = {
    'host': 'sygest-db',
    'user': 'root',
    'password': 'root_pwd_sygest',
    'database': 'progetto_sygest',
    'charset': 'utf8mb4',
    'cursorclass': pymysql.cursors.DictCursor
}

ZABBIX_SERVER = 'zabbix-server'
ZABBIX_PORT = 10051

# Nmap mi restituisce il nome dei software rilevati usando uno standard vecchio chiamato CPE 2.2 (es. cpe:/a:apache:http_server).
# Il database delle vulnerabilità NVD però richiede lo standard aggiornato CPE 2.3.
# Questa funzione converte il vecchio formato in quello nuovo richiesto dal NIST.
def conversion_cpe(cpe_value):
    # Se la stringa non inizia con "cpe:/", significa che non è valida
    if not cpe_value.startswith("cpe:/"): 
        return None
        
    # Sostituisco l'inizio e divido la stringa usando i due punti (:) come separatore
    token = cpe_value.replace("cpe:/", "").split(":")
    
    # Inizio a comporre la nuova stringa aggiungendo "cpe:2.3:"
    cpe_new_value = "cpe:2.3:" + ":".join(token)
    
    # Il formato CPE 2.3 richiede 13 campi separati da ":"
    # Calcolo quanti campi mancano rispetto alla stringa che mi ha fornito Nmap.
    missing_fields = 13 - len(cpe_new_value.split(":"))
    
    # Riempio i campi vuoti aggiungendo degli asterischi che fungono da carattere jolly
    if missing_fields > 0: 
        cpe_new_value += ":*" * missing_fields
        
    return cpe_new_value

# Funzione per leggere il file XML generato da Nmap ed estrarne tutti i codici CPE trovati
def extraction_cpe(file_xml):
    # Uso un oggetto set anziché una normale lista per memorizzare i risultati visto che il set
    # elimina duplcati in automatico
    valid_cpe = set() 
    
    if not os.path.exists(file_xml): 
        return []
        
    # Uso ElementTree per "navigare" la struttura ad albero del file XML
    tree = ET.parse(file_xml)
    
    # Cerco iterativamente ogni singolo tag <cpe> all'interno dell'XML
    for cpe_tag in tree.getroot().findall(".//cpe"):
        if cpe_tag.text:
            # Passo la stringa trovata alla mia funzione di conversione
            cpe_new = conversion_cpe(cpe_tag.text.strip())
            # Se la conversione va a buon fine, l'aggiungo al mio set
            if cpe_new: 
                valid_cpe.add(cpe_new)
                
    # Riconverto il set in una lista standard e lo ritorno
    return list(valid_cpe)

# Questa funzione interroga le API RESTful del NIST per vedere se un software (CPE) ha vulnerabilità note
def nvd_request(cpe_new_value):
    base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    params = {"virtualMatchString": cpe_new_value}
    headers = {"apiKey": API_KEY_NVD}
    
    # Per evitare lo spam al NVD impongo che si possa riprovare la richiesta ad un massimo di 3 volte
    for attempt in range(3):
        try:
            # Effettuo una richiesta GET con un timeout di 20 secondi
            response = requests.get(base_url, params=params, headers=headers, timeout=20)
            
            # Estraggo e ritorno la lista delle vulnerabilità dal JSON
            if response.status_code == 200: 
                return response.json().get("vulnerabilities", [])
                
            # Status 403 (Forbidden) o 503 (Service Unavailable) significano che il server è sovraccarico o mi ha bloccato
            elif response.status_code in [403, 503]: 
                # mi metto in pausa forzata visto che più tentativi falliscono, più lunga sarà la pausa 
                time.sleep(2 * (attempt + 1)) # Ad ogni fallimento aumento la pausa
        except Exception: 
            # In caso di disconnessione di rete, mi fermo 2 secondi e riprovo
            time.sleep(2)
            
    # MODIFICA: Se falliscono tutti e 3 i tentativi, ritorno None (Errore API) anziche' una lista vuota.
    # Cosi' lo script principale capisce che c'e' stato un disastro di rete e si ferma per sicurezza.
    return None

# Dal JSON fornito da NVD estraggo solo i tre dati che mi servono
def extract_cve_details(cve_item):
    # Estraggo il blocco interno 'cve'
    cve_data = cve_item.get('cve', {})
    
    # Ottengo l'ID univoco del CVE (es. CVE-2023-1234)
    cve_id = cve_data.get('id', 'N/A')
    
    desc = "Nessuna descrizione disponibile." # Descrzione di DEFAULT imposta da me
    # Ricavo la descrizione in inglese
    for d in cve_data.get('descriptions', []):
        if d.get('lang') == 'en':
            desc = d.get('value')
            break
            
    patch_link = None
    # Verifico se per questa vulnerabilità è già stata pubblicata una patch correttiva
    # Itero tra i vari link di riferimento e guardo i tag associati.
    for ref in cve_data.get('references', []):
        tags = ref.get('tags', [])
        # Se i tag includono la parola 'Patch' o un 'Vendor Advisory', mi salvo l'URL
        if 'Patch' in tags or 'Vendor Advisory' in tags:
            patch_link = ref.get('url')
            if 'Patch' in tags: break # Il tag 'Patch' è la fonte più affidabile, se lo trovo smetto di cercare
            
    return cve_id, desc, patch_link

# Splitto la stringa CPE per isolare vendor e product da salvare nel DB
def parse_vendor_product(cpe_string):
    parts = cpe_string.split(":")
    # Prendo il 4° e il 5° blocco della stringa se esistono
    vendor = parts[3] if len(parts) > 3 else "Unknown"
    product = parts[4] if len(parts) > 4 else "Unknown"
    return vendor, product

# Questa funzione dice a Nmap di fare una scansione completa delle porte del server
def esegui_nmap(hostname):
    # Uso 'shutil.which' per trovare automaticamente in quale cartella del sistema Linux è installato Nmap
    nmap_path = shutil.which("nmap")
    
    # Genero un nome per il file di output usando espressioni regolari (re.sub) per eliminare
    # eventuali caratteri non validi dell'hostname e prevenire errori di scrittura su file system.
    output_file = f"{re.sub(r'[^a-zA-Z0-9]', '_', hostname)}.xml"
    
    # Costruisco il comando di Nmap
    comando = [
        nmap_path, 
        "-sV", # cerca di determinare le versioni esatte dei servizi in ascolto
        "-Pn",
        "--version-intensity", "9", # Alzo al massimo il livello di test da eseguire
        "--top-ports", "1000", # Analizzo le 1000 porte più comuni per risparmiare tempo
        "--open", 
        hostname, 
        "-oX", # Dico ad Nmap di salvare il risultato in formato XML
        output_file
    ]
    try:
        # Lancio il processo di scansione e attendo che finisca. il FLAG 'check=True' va in eccezione se Nmap fallisce.
        subprocess.run(comando, capture_output=True, text=True, check=True)
        # Se il file XML è stato creato con successo, ritorno il suo nome
        return output_file if os.path.exists(output_file) else None
    except Exception: 
        return None

def run_monitoring():
    connection = None
    try:
        connection = pymysql.connect(**DB_CONFIG)
        with connection.cursor() as cursor:
            # Estraggo dal mio database solo gli host che voglio scansionare attivamente
            cursor.execute("SELECT id, hostname FROM targets WHERE active = 1")
            targets = cursor.fetchall()
            
            sender = Sender(server=ZABBIX_SERVER, port=ZABBIX_PORT)

            for target in targets:
                target_id = target['id']
                hostname = target['hostname']
                print(f"\nZabbix Push vulnerabilita': {hostname}")
                
                # Eseguo la scansione sulle porte del server con Nmap
                xml_file = esegui_nmap(hostname)
                if not xml_file: continue

                # Leggo l'XML e ricavo i cpe dei software trovati
                found_cpes = extraction_cpe(xml_file)
                
                # Interrogo il mio database per ottenere la lista di tutti i CVE che avevo 
                # già rilevato in passato su questo specifico Host
                cursor.execute("SELECT id, cve_id FROM vulnerabilities WHERE target_id = %s", (target_id,))
                
                # Salvo l'elenco in memoria sotto forma di Dizionario {cve_id: id_database}
                existing_db_cves = {row['cve_id']: row['id'] for row in cursor.fetchall()}
                
                new_active_list = []    # Per i nuovi CVE che non erano gia' nel DB
                new_patched_list = []   # Per i CVE che erano gia' nel DB per cui e' uscita una patch
                total_active_count = 0  # Contatore per il conteggio di CVE
                
                # MODIFICA: Variabili per proteggere Zabbix e scovare i vecchi CVE disinstallati
                currently_detected_cves = set()
                api_error_occurred = False
                
                # Inizio ad iterare per ogni software trovato sul server
                for cpe in found_cpes:
                    vendor, product = parse_vendor_product(cpe)
                    
                    # Interrogo il database NVD per quel software
                    vulnerabilities = nvd_request(cpe)
                    
                    # MODIFICA: Controllo "Anti-Disastro"
                    if vulnerabilities is None:
                        print(f" [!] Errore critico API NVD per '{cpe}'. Salto l'host per evitare falsi positivi/negativi.")
                        api_error_occurred = True
                        break
                    
                    # Analizzo ogni vulnerabilità riportata
                    for item in vulnerabilities:
                        cve_id, desc, patch_link = extract_cve_details(item)
                        
                        # Salvo in memoria che oggi ho visto fisicamente questo CVE
                        currently_detected_cves.add(cve_id)
                        
                        # CASO 1:TROVATA PATCH
                        if patch_link:
                            # Verifico se nel mio database era gia' presente questo CVE 
                            if cve_id in existing_db_cves:
                                # Lo inserisco nella lista delle "nuove patch trovate" da mandare a Zabbix
                                new_patched_list.append({"cve_id": cve_id, "vendor": vendor, "product": product, "patch": patch_link})
                                
                                # cancello questo CVE dal mio database,
                                cursor.execute("DELETE FROM vulnerabilities WHERE id = %s", (existing_db_cves[cve_id],))
                        
                        # CASO B: VULNERABILITÀ IRRISOLTA
                        else:
                            total_active_count += 1 # Incremento il contatore di pericolosità generale dell'Host
                            
                            # Verifico se era presente o no nel DB
                            if cve_id not in existing_db_cves:
                                # La inserisco nella lista delle allerte per Zabbix
                                new_active_list.append({"cve_id": cve_id, "vendor": vendor, "product": product, "description": desc})
                                
                                # Inserisco il CVE nel mio database
                                cursor.execute("INSERT INTO vulnerabilities (target_id, vendor, product, cve_id, description) VALUES (%s, %s, %s, %s, %s)", (target_id, vendor, product, cve_id, desc))
                    
                    # Pausa forzata di 0.6 secondi tra un software e l'altro per rispettare le policy del server NVD
                    time.sleep(0.6) 

                # MODIFICA: Se l'API e' caduta a meta' controllo, annullo tutte le query al DB per questo host e vado al prossimo
                if api_error_occurred:
                    connection.rollback()
                    continue

                # MODIFICA: FASE DI PULIZIA "CVE FANTASMA"
                for db_cve_id, db_row_id in existing_db_cves.items():
                    # Se Nmap non ha piu' trovato il software che generava questo CVE...
                    if db_cve_id not in currently_detected_cves:
                        # ...significa che e' stato rimosso o aggiornato! Lo elimino dal DB.
                        cursor.execute("DELETE FROM vulnerabilities WHERE id = %s", (db_row_id,))

                connection.commit()

                # Creo una variabile di testo vuota
                active_text_formatted = ""
                
                # Se la lista dei nuovi CVE contiene tra 1 e 20 elementi, assemblo una stringa formattata
                # per la mail. Se contiene piu' di 20 elementi come accade alla prima scansione del server,
                # decido di non inserire i dettagli testuali. 
                if 0 < len(new_active_list) <= 20:
                    active_text_formatted = "Elenco dettagliato dei nuovi CVE rilevati:\n\n"
                    for cve in new_active_list:
                        active_text_formatted += f"[{cve['cve_id']}] Software: {cve['vendor'].capitalize()} {cve['product']}\n"
                        active_text_formatted += f"Descrizione: {cve['description']}\n\n"

                # Stessa logica di protezione per le patch trovate
                patched_text_formatted = ""
                if 0 < len(new_patched_list) <= 20:
                    patched_text_formatted = "Elenco delle nuove patch disponibili:\n\n"
                    for cve in new_patched_list:
                        patched_text_formatted += f"[{cve['cve_id']}] Software: {cve['vendor'].capitalize()} {cve['product']}\n"
                        patched_text_formatted += f"Download Patch: {cve['patch']}\n\n"

                # Preparo il pacchetto finale da consegnare a Zabbix
                report = {
                    "total_active": total_active_count,
                    "new_active_count": len(new_active_list),
                    "new_patched_count": len(new_patched_list),
                    "new_active_list": new_active_list,
                    "new_patched_list": new_patched_list,
                    "new_active_text": active_text_formatted,
                    "new_patched_text": patched_text_formatted
                }

                packet = [ItemValue(hostname, 'sygest.vuln', json.dumps(report))]
                result = sender.send(packet)
                print(f"Dati inviati a Zabbix: {result}")
                
                # cancello il file XML temporaneo sul disco fisso.
                try: os.remove(xml_file)
                except: pass

    except Exception as e:
        print(f"Errore: {e}")
        # In caso di errore critico, eseguo un rollback per cancellare eventuali modifiche 
        # a metà salvataggio sul database, garantendo così l'integrità dei dati
        if connection: connection.rollback()
    finally:
        if connection: connection.close()

if __name__ == "__main__":
    run_monitoring()