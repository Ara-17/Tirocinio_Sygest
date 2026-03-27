# Permettere al mio script Python di comunicare con il database nel container 'sygest-db'
import pymysql
import os
from config import DB_CONFIG

# Definisco la funzione principale che si occuperà di gestire l'interfaccia a riga di comando
def host_manager():
    # variabile per evitare problemi in caso di fallimento della connesione
    connection = None
    
    try:
        connection = pymysql.connect(**DB_CONFIG)
        
        # Ciclo principale iniziale per la scelta dell'ambiente (WEB o SERVER)
        while True:
            print("\n" + "="*35)
            print("SELEZIONA L'AMBIENTE DA GESTIRE")
            print("="*35)
            print(" [1] Menu Siti Web (Controlli SSL e Header)")
            print(" [2] Menu Server (Vulnerabilità Trivy)")
            print(" [0] Esci completamente")
            
            scelta_menu = input("\nScegli il menu (1, 2 o 0): ").strip()
            
            # OPZIONE 0: ESCI DAL PROGRAMMA
            if scelta_menu == '0':
                print("-----------------------------------\nRicordati di lanciare 'zabbix_sync.py' per applicare le modifiche a Zabbix!")
                break
                
            # Configuro le variabili in base alla scelta dell'utente
            elif scelta_menu == '1':
                tipo_target = 'WEB'
                titolo_menu = "SITI WEB"
                file_import = "web.txt" # Nuovo file per l'importazione WEB
            elif scelta_menu == '2':
                tipo_target = 'SERVER'
                titolo_menu = "SERVER (TRIVY)"
                file_import = "server.txt" # Nuovo file per l'importazione SERVER
            else:
                print("Scelta non valida. Riprova.")
                continue
                
            # Apro un ciclo interno che serve per mantenere il menu attivo a schermo finché non digito '9' o '0'
            while True:
                with connection.cursor() as cursor:
                    # Eseguo la query per leggere i target salvati, filtrando solo quelli della categoria scelta!
                    cursor.execute("SELECT id, hostname, active FROM targets WHERE target_type = %s", (tipo_target,))
                    # Prendo tutti i risultati trovati e li salvo nella variabile 'targets'
                    targets = cursor.fetchall()
                    
                    # Stampo il menu'
                    print("\n" + "="*35)
                    print(f"GESTORE SYGEST - {titolo_menu}")
                    print("="*35)
                    
                    count = 0 # Inizializzo un contatore per contare gli host nella lista
                    
                    for target in targets:
                        count += 1
                        
                        status_icon = "ON" if target['active'] else "OFF"
                        
                        # Stampo la riga con il numero, il nome dell'host e il suo stato attuale
                        print(f" {count}) {target['hostname']} [{status_icon}]")
                    
                    # Stampo le opzioni disponibili per l'utente
                    print("-" * 35)
                    print(" [A] Aggiungi un nuovo record")
                    print(" [R] Rimuovi un record")
                    # Ho aggiornato il testo a schermo per mostrare il nome del file corretto
                    print(f" [I] Importa massivamente da file ({file_import})")
                    print(" [+] Attiva TUTTI")
                    print(" [-] Disattiva TUTTI")
                    print(" [9] Torna al menu precedente")
                    print(" [0] Esci dal programma")

                    # Uso .strip() per togliere eventuali spazi vuoti inseriti per sbaglio 
                    # Uso .upper() per trasformare la lettera in maiuscolo
                    user_input = input("\nDigita il comando da eseguire: ").strip().upper()
                    
                    # OPZIONE 0: ESCI
                    if user_input == '0':
                        # Ricordo all'utente che il DB è aggiornato ma Zabbix no
                        print("-----------------------------------\nRicordati di lanciare 'zabbix_sync.py' per applicare le modifiche a Zabbix!")
                        # Uso return per stoppare immediatamente l'intera funzione Python e chiudere tutto
                        return 
                        
                    # OPZIONE 9: TORNA INDIETRO
                    elif user_input == '9':
                        # Interrompo solo questo ciclo (while interno) per tornare a quello della scelta 1 o 2
                        break
                    
                    # OPZIONE A: AGGIUNGI HOST
                    elif user_input == 'A':
                        new_host = input("Inserisci il nuovo nome (es. example.com o SRV-01): ").strip()
                        # Controllo che non sia vuoto
                        if new_host:
                            # Controllo se l'host esiste già nel database per evitare duplicati
                            # Uso %s per evitare SQL Injection e controllo anche il tipo (WEB/SERVER)
                            cursor.execute("SELECT id FROM targets WHERE hostname = %s AND target_type = %s", (new_host, tipo_target))
                            
                            # Se fetchone() trova una riga, significa che c'è già l'host inserito
                            if cursor.fetchone():
                                print(f"Attenzione: '{new_host}' è già presente come {tipo_target}!")
                            else:
                                # Se non esiste, procedo con l'inserimento. Lo imposto attivo (1) di default
                                cursor.execute("INSERT INTO targets (hostname, target_type, active) VALUES (%s, %s, 1)", (new_host, tipo_target))
                                # Eseguo il commit per rendere la modifica permanente nel database
                                connection.commit()
                                print(f"'{new_host}' salvato nel DB locale!")
                        continue # Salto il resto del codice e faccio ricominciare il ciclo (mostrando il menu aggiornato)

                    # OPZIONE R: RIMUOVI HOST
                    elif user_input == 'R':
                        try:
                            # Chiedo quale numero dalla lista vuole eliminare e lo converto in int
                            del_id = int(input("Inserisci il NUMERO da rimuovere: ").strip())
                            
                            # Controllo che il numero inserito sia effettivamente compreso tra quelli disponibili
                            if 1 <= del_id <= len(targets):
                                # Recupero i dati dell'host selezionato (ricordando che le liste in Python partono da 0)
                                target_to_del = targets[del_id - 1]
                                
                                # Per sicurezza, chiedo una conferma prima di fare danni irreparabili
                                confirm = input(f"Eliminare definitivamente '{target_to_del['hostname']}' dal DB? (S/N): ").strip().upper()
                                
                                if confirm == 'S':
                                    # Elimino l'host usando il suo ID
                                    cursor.execute("DELETE FROM targets WHERE id = %s", (target_to_del['id'],))
                                    connection.commit()
                                    print(f"Rimosso con successo!")
                        except ValueError:
                            # Se l'utente digita una lettera invece di un numero per la rimozione, 
                            # catturo l'errore ValueError e lo ignoro col comando pass e ricomincia il menu'
                            pass
                        continue # Faccio ricominciare il ciclo
                    
                    # OPZIONE I: IMPORTA DA FILE
                    elif user_input == 'I':
                        # Ora usa la variabile file_import che cambia dinamicamente in base al menu scelto
                        file_path = file_import
                        
                        # Controllo se il file esiste
                        if not os.path.exists(file_path):
                            print(f"Errore: Il file '{file_path}' non è stato trovato nella cartella corrente!")
                            continue
                        
                        try:
                            with open(file_path, 'r') as f:
                                lines = f.readlines()
                            
                            inseriti = 0
                            duplicati = 0
                            
                            for line in lines:
                                new_host = line.strip()
                                # Ignoro le righe vuote e quelle che iniziano con # (commenti)
                                if new_host and not new_host.startswith('#'):
                                    cursor.execute("SELECT id FROM targets WHERE hostname = %s AND target_type = %s", (new_host, tipo_target))
                                    if cursor.fetchone():
                                        duplicati += 1
                                    else:
                                        cursor.execute("INSERT INTO targets (hostname, target_type, active) VALUES (%s, %s, 1)", (new_host, tipo_target))
                                        inseriti += 1
                            
                            # Salvo tutte le modifiche in blocco
                            connection.commit()
                            print(f"\nImportazione completata con successo nella categoria {titolo_menu}!")
                            print(f" - Aggiunti: {inseriti}")
                            print(f" - Ignorati (già presenti): {duplicati}")
                        
                        except Exception as e:
                            print(f"Errore durante la lettura del file: {e}")
                        continue

                    # OPZIONE +: ATTIVA TUTTI
                    elif user_input == '+':
                        if not targets:
                            print("Nessun record presente in questa lista.")
                            continue
                        
                        # Controllo se sono già tutti accesi (tutti hanno active == 1)
                        if all(t['active'] == 1 for t in targets):
                            print("Ottimo! Tutti i record della lista sono GIÀ ATTIVI.")
                        else:
                            confirm = input("Sei sicuro di voler ATTIVARE TUTTI i record di questa lista? (S/N): ").strip().upper()
                            if confirm == 'S':
                                # Aggiorno a 1 solo quelli della categoria in cui mi trovo
                                cursor.execute("UPDATE targets SET active = 1 WHERE target_type = %s", (tipo_target,))
                                connection.commit()
                                print("Operazione completata: Tutti i record sono stati attivati!")
                        continue

                    # OPZIONE -: DISATTIVA TUTTI
                    elif user_input == '-':
                        if not targets:
                            print("Nessun record presente in questa lista.")
                            continue
                        
                        # Controllo se sono già tutti spenti (tutti hanno active == 0)
                        if all(t['active'] == 0 for t in targets):
                            print("Tutti i record della lista sono GIÀ DISATTIVATI.")
                        else:
                            confirm = input("ATTENZIONE: Sei sicuro di voler DISATTIVARE TUTTI i record di questa lista? (S/N): ").strip().upper()
                            if confirm == 'S':
                                # Aggiorno a 0 solo quelli della categoria in cui mi trovo
                                cursor.execute("UPDATE targets SET active = 0 WHERE target_type = %s", (tipo_target,))
                                connection.commit()
                                print("Operazione completata: Tutti i record sono stati disattivati!")
                        continue

                    # CAMBIO STATO (ON/OFF) - Numerico SINGOLO
                    try:
                        # Tento di convertire l'input in un numero intero
                        selected = int(user_input)
                        
                        # Verifico che il numero sia valido
                        if 1 <= selected <= len(targets):
                            target = targets[selected - 1]
                            
                            new_status = 0 if target['active'] else 1
                            
                            # Aggiorno il database con il nuovo stato
                            cursor.execute("UPDATE targets SET active = %s WHERE id = %s", (new_status, target['id']))
                            connection.commit()
                            print(f"Lo stato di '{target['hostname']}' e' stato aggiornato!")
                    except ValueError:
                        pass

    except Exception as e:
        # Questo blocco scatta solo se ci sono errori come database spento o password sbagliata
        print(f"Errore Database: {e}")
        
    finally:
        if connection: 
            # Chiudo la connessione al database per non sprecare risorse del server
            connection.close()

# Evito di avviare lo script se usassi questo file come libreria in un altro script
if __name__ == "__main__":
    host_manager()