import pymysql

# Imposto i parametri per collegarmi al database locale
DB_CONFIG = {
    'host': 'sygest-db',
    'user': 'root',
    'password': 'root_pwd_sygest',
    'database': 'progetto_sygest',
    'charset': 'utf8mb4',
    # Uso i dizionari per poter chiamare le colonne col loro nome
    'cursorclass': pymysql.cursors.DictCursor
}

def visualizza_vulnerabilita():
    connection = None
    try:
        # Apro la connessione col DB
        connection = pymysql.connect(**DB_CONFIG)
        with connection.cursor() as cursor:
            
            # Faccio una query JOIN per prendere le vulnerabilità dei target accesi
            # Ordino i risultati prima per nome dell host e poi per ID del CVE
            query = """
                SELECT 
                    t.hostname, 
                    v.cve_id, 
                    v.software, 
                    v.current_version, 
                    v.fixed_version, 
                    v.link_patch,
                    v.description 
                FROM targets t
                JOIN vulnerabilities v ON t.id = v.target_id
                WHERE t.active = 1
                ORDER BY t.hostname, v.cve_id
            """
            
            cursor.execute(query)
            risultati = cursor.fetchall()

            if not risultati:
                print("\nNessuna vulnerabilita trovata nel DB per gli host attualmente attivi")
                return

            host_corrente = ""
            vuln_count = 0

            # Scorro riga per riga i risultati del database
            for row in risultati:
                
                # Appena lo script passa a un server diverso stampo un instestazione nuova
                if row['hostname'] != host_corrente:
                    host_corrente = row['hostname']
                    print("\n" + "="*30)
                    print(f" REPORT VULNERABILITA SALVATE")
                    print("="*30)
                    print(f"\nHOSTNAME: {host_corrente}\n")
                    # Azzero il contatore per il nuovo server
                    vuln_count = 0

                vuln_count += 1
                
                # Pulisco i dati vuoti per non far stampare la scritta None di Python
                patch = row['fixed_version'] if row['fixed_version'] else "Nessuna patch disponibile"
                link = row['link_patch'] if row['link_patch'] else "Non disponibile"
                
                # Stampo a terminale esattamente col formato che mi serviva
                print(f"SOFTWARE {row['software']}")
                print(f"  - CVE               {row['cve_id']}")
                print(f"  - Versione Attuale  {row['current_version']}")
                print(f"  - Aggiornamenti     {patch}")
                print(f"  - Link Patch/Info   {link}")
                print(f"  - Descrizione       {row['description']}")
                print("-" * 80)

    except Exception as e:
        print(f"Ho riscontrato un errore durante l interrogazione del database {e}")
        
    finally:
        # Chiudo la connessione
        if connection:
            connection.close()

if __name__ == '__main__':
    visualizza_vulnerabilita()