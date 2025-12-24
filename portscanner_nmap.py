Este projeto é apenas para fins educacionais.
Não utilize para escanear redes sem autorização.

import nmap
import datetime

scanner  = nmap.PortScanner()

#IP ou dominio que vamos analisar
alvo = "scanner.nmap.org"

#Intervalo de portas 
portas = "20-100"

print(f"iniciando varredura no alvo {alvo}...")
scanner.scan(alvo, portas, arguments= "-sV")
 
#criar nome de arquivo com data 

data_atual = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
nome_arquivo = f"relatorio_{data_atual}.txt"


#salvando os resultados nos arquivo
with open(nome_arquivo, "w", encoding="utf-8") as relatorio:

    for host in scanner.all_hosts():
        relatorio.write(f"Host: {host} ({scanner[host].hostname()}\n)")
        relatorio.write(f"STATUS: ({scanner[host].state()}\n")
        for protocolo in scanner[host].all_protocols():
          portas_abertas = scanner[host][protocolo].keys()

        for porta in portas_abertas:
            servico = scanner[host][protocolo][porta]['name']
            versao = scanner[host][protocolo][porta].get('version', "N⁄A")
            relatorio.write(f"Porta {porta}⁄{protocolo} -> {versao}\n")

print(f"Varredura concluida! Relatorio salvo como {nome_arquivo}")
