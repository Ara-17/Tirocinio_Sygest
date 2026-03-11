Per far partire il docker, bisogna posizionarsi nella cartella del progetto e usare il comando: Docker compose up -d
Una volta che saranno pariti i container, possiamo visualizzare la dashbord di zabbix andando sul browser digitando "localhost:8080". Le credenziali per l'accessono sono USER = admin e PASSWORD = zabbix. 
Per far partire gli script bisogna digitare il comando: docker exec -it sygest-script-runner python [nome_script.py]. Il primo script da usare è "zabbix_sync.py" che permette di allineare i dati del DB con zabbix. 
Il file "host_manager_script.py" permette di attivare o disattivare un host nel controllo, aggiungere e/o rimuovere un host. Per ogni modifica fatta bisogna sempre far partire lo script "zabbix_sync.py" per allineare le modifche del DB.
Il file "zabbix_ssl_headers.py" permette di fare la lettura delle scadenze SSL come il CA e il thumbprint
Il file "zabbix_vuln_checker.py" permette di fare la rilevazione dei CVE di un host attraverso nmap e poi i risultati venivano interrogati sul DB di NVD
