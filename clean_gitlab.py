import os
import requests
from dotenv import load_dotenv

# Carico le stesse credenziali dal file .env che usano gli altri script
load_dotenv()

GITLAB_URL = os.getenv('GITLAB_URL', 'https://gitlab.com')
GITLAB_TOKEN = os.getenv('GITLAB_TOKEN')
GITLAB_PROJECT_ID = os.getenv('GITLAB_PROJECT_ID')

def pulisci_bacheca_gitlab():
    print("\nInizio la pulizia massiva delle Issue su GitLab...")
    
    # Preparo l'header con il token segreto per farmi riconoscere da GitLab
    headers = {
        'PRIVATE-TOKEN': GITLAB_TOKEN
    }
    
    # Costruisco l'URL per chiedere a GitLab la lista di tutte le Issue di questo progetto.
    # Il parametro ?per_page=100 serve a ricavarne fino a 100 in un colpo solo.
    url_lettura = f"{GITLAB_URL}/api/v4/projects/{GITLAB_PROJECT_ID}/issues?per_page=100"
    
    # Faccio la chiamata GET
    risposta = requests.get(url_lettura, headers=headers)
    
    # Controllo che il server abbia risposto con un OK (200)
    if risposta.status_code != 200:
        print(f"Errore di connessione a GitLab. Codice HTTP: {risposta.status_code}")
        print(f"Dettaglio: {risposta.text}")
        return

    # Trasformo la risposta da stringa a lista di dizionari Python
    issues = risposta.json()
    
    if not issues:
        print("Nessuna Issue trovata nel progetto. La bacheca è già pulita!")
        return
        
    print(f"Trovate {len(issues)} Issue. Preparo la distruzione totale...")
    
    # Scorro una per una le Issue trovate
    for issue in issues:
        # Prendo l'ID univoco interno del ticket (iid) e il suo titolo
        issue_iid = issue['iid']
        titolo = issue['title']
        
        # Costruisco l'URL specifico per distruggere questa singola issue
        url_cancellazione = f"{GITLAB_URL}/api/v4/projects/{GITLAB_PROJECT_ID}/issues/{issue_iid}"
        
        # Mando il comando DELETE
        del_resp = requests.delete(url_cancellazione, headers=headers)
        
        # Se GitLab risponde 204 significa "No Content", ovvero cancellato con successo
        if del_resp.status_code == 204:
            print(f"Eliminata: [#{issue_iid}] {titolo}")
        else:
            print(f"Errore su #{issue_iid}: {del_resp.text}")

    print("\nPulizia terminata con successo! La tua bacheca è come nuova")

if __name__ == "__main__":
    # Eseguo un controllo di sicurezza per assicurarmi di avere il Token
    if not GITLAB_TOKEN or not GITLAB_PROJECT_ID:
        print("Errore: Manca il GITLAB_TOKEN o il GITLAB_PROJECT_ID nel file .env!")
    else:
        pulisci_bacheca_gitlab()