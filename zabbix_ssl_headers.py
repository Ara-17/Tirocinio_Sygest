import socket
import json # serve per convertire i dati in un formato compatibile con Zabbix
import subprocess # permette di eseguire comandi del sistema operativo (come testssl.sh o nuclei)
import sys # permette di recuperare l'eseguibile Python corrente
import os
import requests
import pymysql
import time # Aggiunto per gestire la pausa dell'interruttore Zabbix
from datetime import datetime, timezone

# Importo le classi ufficiali della libreria Zabbix per inviare dati in modalità passiva
from zabbix_utils import Sender, ItemValue

from config import DB_CONFIG, ZABBIX_SERVER, ZABBIX_PORT

# ==========================================
# DIZIONARI TESTI UFFICIALI
# ==========================================
HEADER_DESCRIPTIONS = {
    'content-security-policy': 'Content Security Policy is an effective measure to protect your site from XSS attacks.',
    'x-frame-options': 'X-Frame-Options tells the browser whether you want to allow your site to be framed or not.',
    'x-content-type-options': 'X-Content-Type-Options stops a browser from trying to MIME-sniff the content type.',
    'strict-transport-security': 'HTTP Strict Transport Security strengthens your implementation of TLS.',
    'referrer-policy': 'Referrer Policy allows a site to control how much information the browser includes.',
    'permissions-policy': 'Permissions Policy allows a site to control which features and APIs can be used.'
}

UPCOMING_DESCRIPTIONS = {
    'cross-origin-embedder-policy': '**Cross-Origin-Embedder-Policy** allows a site to prevent assets being loaded that do not grant permission to load them via CORS or CORP.',
    'cross-origin-opener-policy': '**Cross-Origin-Opener-Policy** allows a site to opt-in to Cross-Origin Isolation in the browser.',
    'cross-origin-resource-policy': '**Cross-Origin-Resource-Policy** allows a resource owner to specify who can load the resource.'
}


# ==========================================
# MOTORI DI SCANSIONE
# ==========================================

# Definisco una funzione per analizzare il certificato SSL tramite il tool esterno testssl.sh
def analizza_ssl(hostname):
    print(f"-> [{hostname}] Esecuzione testssl.sh in corso...")
    json_path = f"/tmp/{hostname}_ssl.json"
    
    # Elimino il file vecchio se esiste per non avere dati sporchi
    if os.path.exists(json_path): 
        os.remove(json_path)

    try:
        # Uso 'subprocess.run' per eseguire testssl limitando il timeout a 5 minuti per evitare blocchi
        result = subprocess.run(
            ["testssl.sh", "--quiet", "--fast", "--jsonfile", json_path, f"https://{hostname}"], 
            capture_output=True, 
            text=True, 
            timeout=300
        )
        
        if not os.path.exists(json_path):
            err_msg = result.stderr.strip() if result.stderr else "Nessun errore restituito dal terminale."
            return {"error": f"File JSON non creato. Dettaglio: {err_msg[:200]}"}

        # Leggo il JSON generato da testssl
        with open(json_path, 'r') as f:
            ssl_data = json.load(f)

        risultati = {"grade": "N/A", "scadenza_data": "N/A", "days_left": None, "thumbprint": "N/A", "warnings": []}

        # Analizzo riga per riga l'output per cercare grado, scadenza, impronta e vulnerabilità note
        for item in ssl_data:
            id_item = item.get("id", "")
            finding = item.get("finding", "")
            sev = item.get("severity", "")

            if id_item == "overall_grade": 
                risultati["grade"] = finding
            elif id_item == "cert_notAfter": 
                # Estraggo solo la data esatta (es. 2026-04-25) ignorando l'orario per il report
                date_str = finding.split(" ")[0] 
                risultati["scadenza_data"] = date_str
                try:
                    # Calcolo la differenza matematica tra la scadenza e la data di oggi per ottenere i giorni rimanenti
                    exp_date = datetime.strptime(date_str, "%Y-%m-%d").date()
                    oggi = datetime.now(timezone.utc).date()
                    risultati["days_left"] = (exp_date - oggi).days
                except:
                    pass
            elif id_item == "cert_fingerprintSHA256": 
                risultati["thumbprint"] = finding
            elif "grade_cap_reason" in id_item:
                # Uso la checkbox e aggiungo le label di GitLab in coda, togliendo la scritta fissa
                risultati["warnings"].append(f"- [ ] {id_item}: {finding} ~\"warning\" ~\"criticità::media\"")
            elif sev in ["HIGH", "CRITICAL", "MEDIUM"] and id_item not in ["security_headers", "overall_grade"]:
                label = '~"criticità::alta"' if sev in ["HIGH", "CRITICAL"] else '~"criticità::media"'
                # Uso la checkbox e aggiungo le label di GitLab in coda, togliendo la scritta fissa
                risultati["warnings"].append(f"- [ ] {id_item}: {finding} ~\"vulnerabilità\" {label}")
                    
        return risultati
        
    except subprocess.TimeoutExpired:
        return {"error": "Timeout superato (5 minuti). Lo scanner SSL si è impallato nel firewall."}
    except Exception as e:
        return {"error": str(e)}

# Funzione per analizzare gli Header HTTPS sfruttando Nuclei e regole personalizzate (Linting)
def analizza_headers(hostname):
    print(f"-> [{hostname}] Esecuzione Nuclei + Linting in corso...")
    json_path = f"/tmp/{hostname}_headers.json"
    
    # Elimino il file vecchio se esiste per non avere dati sporchi
    if os.path.exists(json_path): 
        os.remove(json_path)

    try:
        try: 
            ip_address = socket.gethostbyname(hostname)
        except: 
            ip_address = "Sconosciuto"

        # Catturo gli header nativi del server per fare le valutazioni interne sul testo (Linting)
        try:
            req = requests.get(f"https://{hostname}", timeout=10)
            # Li metto in minuscolo per fare la ricerca in modo più semplice dopo
            raw_headers = {k.lower(): v for k, v in req.headers.items()}
            veri_raw_headers = dict(req.headers)
            http_status = f"HTTP/1.1 {req.status_code} {req.reason}"
        except:
            raw_headers = {}
            veri_raw_headers = {"Errore": "Connessione fallita"}
            http_status = "N/A"

        # Eseguo Nuclei mirato solo agli header, con limiti di rete per non farsi bannare
        subprocess.run(
            [
                "nuclei", 
                "-u", f"https://{hostname}", 
                "-t", "http/missing-security-headers.yaml", 
                "-it", "http", 
                "-max-host-error", "5", 
                "-retries", "1", 
                "-rl", "150", 
                "-json-export", json_path
            ], 
            capture_output=True, 
            timeout=300
        )

        missing_nuclei = []
        if os.path.exists(json_path) and os.path.getsize(json_path) > 0:
            with open(json_path, 'r') as f:
                try:
                    for vuln in json.load(f):
                        if vuln.get("template-id") == "http-missing-security-headers":
                            missing_nuclei.append(vuln.get("matcher-name", "").lower())
                except: 
                    pass

        score = 100
        missing_list = []
        present_list = []
        warnings = []
        
        # Algoritmo di calcolo del punteggio a sottrazione
        for h_key in HEADER_DESCRIPTIONS.keys():
            if h_key in missing_nuclei or h_key not in raw_headers:
                label = '~"criticità::alta"' if h_key in ['content-security-policy', 'x-frame-options', 'strict-transport-security', 'x-content-type-options'] else '~"criticità::media"'
                # Aggiungo alla lista dei mancanti con la sua checkbox e l'etichetta
                missing_list.append(f"- [ ] {h_key.title()} {label}")
                score -= 15
            else:
                present_list.append(f"`{h_key.title()}`")
                valore = raw_headers[h_key].lower()
                
                # Regole specifiche di Linting con Checkbox e Label
                if h_key == 'content-security-policy':
                    if any(x in valore for x in ['unsafe-inline', 'unsafe-eval', 'unsafe-hashes']):
                        warnings.append(f"- [ ] Content-Security-Policy: Contiene direttive unsafe ~\"warning\" ~\"criticità::media\"")
                        score -= 10
                    if '*' in valore:
                        warnings.append(f"- [ ] Content-Security-Policy: Contiene wildcard '*' ~\"warning\" ~\"criticità::media\"")
                        score -= 5
                    if 'default-src' not in valore:
                        warnings.append(f"- [ ] Content-Security-Policy: Manca default-src ~\"warning\" ~\"criticità::media\"")
                        score -= 5
                    if 'frame-ancestors' not in valore:
                        warnings.append(f"- [ ] Content-Security-Policy: Manca frame-ancestors ~\"warning\" ~\"criticità::media\"")
                        score -= 5

                if h_key == 'x-frame-options' and 'allow-from' in valore:
                    warnings.append(f"- [ ] X-Frame-Options: ALLOW-FROM è deprecato. ~\"warning\" ~\"criticità::bassa\"")
                    score -= 5
                if h_key == 'x-content-type-options' and 'nosniff' not in valore:
                    warnings.append(f"- [ ] X-Content-Type-Options: Valore non nosniff ~\"warning\" ~\"criticità::media\"")
                    score -= 5

        upcoming_list = []
        for u_key, desc in UPCOMING_DESCRIPTIONS.items():
            if u_key in missing_nuclei or u_key not in raw_headers:
                # Trasformati in checkbox con label upcoming al posto dei normali bullet point
                upcoming_list.append(f"- [ ] {desc} ~\"upcoming\"")
        
        # Controllo se il server spiffera la sua versione esatta tramite l'header
        for info_hdr in ['server', 'x-powered-by', 'x-aspnet-version']:
            if info_hdr in raw_headers and raw_headers[info_hdr].strip() != "":
                warnings.append(f"- [ ] {info_hdr.title()}: Possibile information disclosure (`{raw_headers[info_hdr][:30]}`) ~\"warning\" ~\"criticità::bassa\"")
                score -= 5

        # Controlli di sicurezza sui Cookie
        if 'set-cookie' in raw_headers:
            cookie_val = raw_headers['set-cookie'].lower()
            if 'secure' not in cookie_val: 
                warnings.append(f"- [ ] Set-Cookie: Manca Secure ~\"warning\" ~\"criticità::media\"")
            if 'httponly' not in cookie_val: 
                warnings.append(f"- [ ] Set-Cookie: Manca HttpOnly ~\"warning\" ~\"criticità::media\"")
            if 'samesite' not in cookie_val: 
                warnings.append(f"- [ ] Set-Cookie: Manca SameSite ~\"warning\" ~\"criticità::bassa\"")
            
        # Controllo configurazioni CORS pericolose
        acao = raw_headers.get('access-control-allow-origin', '').strip()
        acac = raw_headers.get('access-control-allow-credentials', '').strip().lower()
        if acao == '*' and 'true' in acac:
            warnings.append(f"- [ ] CORS: Origin=* con credenziali=true ~\"vulnerabilità\" ~\"criticità::alta\"")
            score -= 15

        # Normalizzo lo score impedendo che scenda sotto zero
        score = max(0, min(score, 100))
        
        # NUOVA SCALA VOTI PONDERATA (0-10 F, 10-20 E, 20-40 D, 40-60 C, 60-80 B, 80-90 A, 90-100 A+)
        if score >= 90: grade = "A+"
        elif score >= 80: grade = "A"
        elif score >= 60: grade = "B"
        elif score >= 40: grade = "C"
        elif score >= 20: grade = "D"
        elif score >= 10: grade = "E"
        else: grade = "F"

        return {
            "score": score, 
            "grade": grade, 
            "ip_address": ip_address, 
            "http_status": http_status,
            "missing_list": missing_list, 
            "missing_count": len(missing_list), 
            "present_list": present_list,
            "warnings": warnings, 
            "upcoming_list": upcoming_list, 
            "raw_headers": veri_raw_headers, 
            "error": None
        }
    except Exception as e:
        return {"error": str(e)}

# ==========================================
# 3. GENERAZIONE REPORT E INVIO A ZABBIX E DB
# ==========================================

# Funzione che raccoglie i dati, formatta il Markdown per GitLab, salva su DB locale e prepara il JSON per Zabbix
def genera_e_invia_report(hostname, target_id, db_connection):
    
    # Chiamo le mie due funzioni per recuperare i dati dell'host corrente
    ssl_data = analizza_ssl(hostname)
    h_data = analizza_headers(hostname)

    # Se gli scanner mi restituiscono un errore, fermo tutto e non aggiorno i dati
    if ssl_data.get("error") or h_data.get("error"):
        print(f"[X] {hostname} saltato per errori di rete.")
        return None

    # Formattazione del Markdown per la Issue di GitLab (Con sezioni collassabili richieste dal CTO)
    report_time = datetime.now(timezone.utc).strftime("%d %b %Y %H:%M:%S UTC")
    
    testo = f"## Security Report: {hostname}\n\n"
    
    # Blocco Report Summary (Collassabile)
    testo += "<details><summary><b>Report Summary</b></summary>\n\n"
    testo += "| Metrica | Valore |\n|---|---|\n"
    testo += f"| Site | `https://{hostname}` |\n"
    testo += f"| IP Address | `{h_data['ip_address']}` |\n"
    testo += f"| Report Time | `{report_time}` |\n"
    testo += f"| Headers Grade | {h_data['grade']} (Score: {h_data['score']}/100) |\n"
    testo += f"| Headers Presenti | {' '.join(h_data['present_list']) if h_data['present_list'] else '*Nessuno*'} |\n"
    testo += f"| SSL Grade | {ssl_data.get('grade', 'N/A')} |\n"
    testo += f"| SSL Scadenza Data | `{ssl_data.get('scadenza_data', 'N/A')}` |\n"
    testo += f"| SSL Giorni Rimanenti | `{ssl_data.get('days_left', 'N/A')} giorni` |\n"
    testo += f"| SSL Thumbprint | `{ssl_data.get('thumbprint', 'N/A')}` |\n\n"
    testo += "</details>\n\n"

    # Blocco Missing Headers & Criticità (Collassabile)
    if h_data['missing_list']:
        testo += "<details><summary><b>Missing Headers & Criticità</b></summary>\n\n"
        testo += "\n".join(h_data['missing_list']) + "\n\n"
        testo += "</details>\n\n"
        
    # Blocco Upcoming Headers (Collassabile)
    if h_data['upcoming_list']:
        testo += "<details><summary><b>Upcoming Headers</b></summary>\n\n"
        testo += "\n".join(h_data['upcoming_list']) + "\n\n"
        testo += "</details>\n\n"

    # Rimozione Duplicati
    all_warnings_raw = h_data['warnings'] + ssl_data['warnings']
    all_warnings = list(dict.fromkeys(all_warnings_raw))
    
    # Blocco Vulnerabilities & Warnings (Collassabile)
    if all_warnings:
        testo += "<details><summary><b>Vulnerabilities & Warnings</b></summary>\n\n"
        testo += "\n".join(all_warnings) + "\n\n"
        testo += "</details>\n\n"

    # Blocco Raw Headers (Collassabile)
    testo += "<details><summary><b>Raw Headers</b></summary>\n\n"
    testo += f"{h_data['http_status']}\n\n"
    testo += "| Header | Valore |\n|---|---|\n"
    for k, v in h_data['raw_headers'].items():
        testo += f"| {k} | `{v}` |\n"
    testo += "\n</details>\n\n"

    # Salvataggio della "Fotografia" nel Database MariaDB
    try:
        with db_connection.cursor() as cursor:
            warnings_str = "\n".join(all_warnings)
            cursor.execute("""
                INSERT INTO scans (target_id, score, headers_grade, ssl_grade, days_left, thumbprint, warnings_text, full_report)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            """, (target_id, h_data['score'], h_data['grade'], ssl_data.get('grade', 'N/A'), 
                  ssl_data.get('days_left'), ssl_data.get('thumbprint', 'N/A'), warnings_str, testo))
            db_connection.commit()
    except Exception as e:
        print(f"Errore salvataggio DB: {e}")

    # Creazione del Payload JSON che verrà spedito al Master Item di Zabbix
    zabbix_payload = {
        "score": h_data['score'],
        "headers_grade": h_data['grade'],
        "ssl_grade": ssl_data.get('grade', 'N/A'),
        "days_left": ssl_data.get('days_left', -1) if ssl_data.get('days_left') is not None else -1,
        "thumbprint": ssl_data.get('thumbprint', 'N/A'),
        "missing_count": h_data['missing_count'],
        "warnings_text": "\n".join(all_warnings) if all_warnings else "Nessun warning rilevato.",
        "full_markdown_report": testo
    }
    
    return zabbix_payload

# Definisco la funzione principale che avvia il monitoraggio
def run_monitoring():
    connection = None
    try:
        # Mi collego al database passando i parametri del DB_CONFIG tramite **
        connection = pymysql.connect(**DB_CONFIG)
        with connection.cursor() as cursor:
            # Chiedo al database l'elenco dei soli target attivi recuperando anche il loro ID
            cursor.execute("SELECT id, hostname FROM targets WHERE active = 1")
            targets = cursor.fetchall()
            
            # Inizializzo l'oggetto 'Sender' che si occuperà di spedire i dati a Zabbix
            sender = Sender(server=ZABBIX_SERVER, port=ZABBIX_PORT)

            # Itero tutti gli host trovati nel database
            for target in targets:
                hostname = target['hostname']
                print(f"\nAnalisi Zabbix/DB in corso: {hostname}")

                # Chiamo la funzione per generare il report e il JSON
                payload = genera_e_invia_report(hostname, target['id'], connection)
                
                if payload:
                    # Creo gli oggetti 'ItemValue', il formato richiesto da Zabbix per ricevere i dati.
                    # Richiede il nome dell'Host in Zabbix, la "Key" dell'Item, e il Valore.
                    # Oltre al payload JSON invio e ACCENDO l'interruttore (valore 1) per forzare 
                    # Zabbix a eseguire il trigger e lanciare il Webhook per i controlli di Routine.
                    packet = [
                        ItemValue(hostname, 'sygest.ssl_headers', json.dumps(payload)),
                        ItemValue(hostname, 'sygest.scan_status', 1) 
                    ]
                    
                    # Invio il pacchetto tramite la rete a Zabbix
                    result = sender.send(packet)
                    print(f"Dati inviati a Zabbix per {hostname}: {result}")
                    
                    # Aspetto 2 secondi e SPENGO l'interruttore (valore 0) inviandolo a Zabbix.
                    # In questo modo i problemi sulla Dashboard tornano "Verdi" e si azzerano
                    # fino alla prossima scansione.
                    time.sleep(2)
                    packet_close = [ItemValue(hostname, 'sygest.scan_status', 0)]
                    sender.send(packet_close)

    except Exception as e:
        print(f"Errore critico: {e}")
    finally:
        if connection: 
            connection.close()

if __name__ == "__main__":
    run_monitoring()