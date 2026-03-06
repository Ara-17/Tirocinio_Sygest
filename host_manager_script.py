# Permettere al mio script Python di comunicare con il database nel container 'sygest-db'
import pymysql

# Creo un dizionario di configurazione
DB_CONFIG = {
    'host': 'sygest-db',           # Nome del container Docker che fa da database
    'user': 'root',                # Utente amministratore del database
    'password': 'root_pwd_sygest', # Password che ho impostato nel docker-compose
    'database': 'progetto_sygest', # Il nome del mio database
    'charset': 'utf8mb4',          # Uso utf8mb4 per supportare tutti i caratteri speciali
    # Chiedo a pymysql di restituirmi i risultati delle query sotto forma di dizionari 
    'cursorclass': pymysql.cursors.DictCursor
}

# Definisco la funzione principale che si occuperà di gestire l'interfaccia a riga di comando
def host_manager():
    # variabile per evitare problemi in caso di fallimento della connesione
    connection = None
    
    try:
        connection = pymysql.connect(**DB_CONFIG)
        
        # Apro un ciclo che serve per mantenere il menu attivo a schermo finché 
        # non digito '0'
        while True:
            with connection.cursor() as cursor:
                # Eseguo la query per leggere tutti i miei target salvati
                cursor.execute("SELECT id, hostname, active FROM targets")
                # Prendo tutti i risultati trovati e li salvo nella variabile 'targets'
                targets = cursor.fetchall()
                
                # Stampo il menu'
                print("\n" + "="*35)
                print("GESTORE HOST SYGEST (Database)")
                print("="*35)
                
                count = 0 # Inizializzo un contatore per contare gli host nella lista
                
                for target in targets:
                    count += 1
                    
                    status_icon = "ON" if target['active'] else "OFF"
                    
                    # Stampo la riga con il numero, il nome dell'host e il suo stato attuale
                    print(f" {count}) {target['hostname']} [{status_icon}]")
                
                # Stampo le opzioni disponibili per l'utente
                print("-" * 35)
                print(" [A] Aggiungi un nuovo Host")
                print(" [R] Rimuovi un Host")
                print(" [0] Esci")

                # Uso .strip() per togliere eventuali spazi vuoti inseriti per sbaglio 
                # Uso .upper() per trasformare la lettera in maiuscolo
                user_input = input("\nDigita il comando da eseguire: ").strip().upper()
                
                # OPZIONE 0: ESCI
                if user_input == '0':
                    # Ricordo all'utente che il DB è aggiornato ma Zabbix no
                    print("\nRicordati di lanciare 'zabbix_sync.py' per applicare le modifiche a Zabbix!\n")
                    break 
                
                # OPZIONE A: AGGIUNGI HOST
                elif user_input == 'A':
                    new_host = input("Inserisci il nuovo hostname (es. example.com): ").strip()
                    # Controllo che non sia vuoto
                    if new_host:
                        # Controllo se l'host esiste già nel database per evitare duplicati
                        # Uso %s per evitare SQL Injection
                        cursor.execute("SELECT id FROM targets WHERE hostname = %s", (new_host,))
                        
                        # Se fetchone() trova una riga, significa che c'è già l'host inserito
                        if cursor.fetchone():
                            print(f"Attenzione: L'host '{new_host}' è già presente!")
                        else:
                            # Se non esiste, procedo con l'inserimento. Lo imposto attivo (1) di default
                            cursor.execute("INSERT INTO targets (hostname, active) VALUES (%s, 1)", (new_host,))
                            # Eseguo il commit per rendere la modifica permanente nel database
                            connection.commit()
                            print(f"'{new_host}' salvato nel DB locale!")
                    continue # Salto il resto del codice e faccio ricominciare il ciclo (mostrando il menu aggiornato)

                # OPZIONE R: RIMUOVI HOST
                elif user_input == 'R':
                    try:
                        # Chiedo quale numero dalla lista vuole eliminare e lo converto in int
                        del_id = int(input("Inserisci il NUMERO dell'Host da rimuovere: ").strip())
                        
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
                                print(f"Host rimosso con successo!")
                    except ValueError:
                        # Se l'utente digita una lettera invece di un numero per la rimozione, 
                        # catturo l'errore ValueError e lo ignoro col comando pass e ricomincia il menu'
                        pass
                    continue # Faccio ricominciare il ciclo

                # CAMBIO STATO (ON/OFF)
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