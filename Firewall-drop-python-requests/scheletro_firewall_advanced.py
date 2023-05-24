#! /usr/bin/env python3 
from scapy.all import *
from netfilterqueue import NetfilterQueue
#import psutil
import os
import time
import binascii
import io
import gzip


#Metto in coda tutte le TCP connections con destinazione e con sorgente la porta del mio servizio
#os.system("iptables -A INPUT -p tcp --dport 8080 -m state --state ESTABLISHED -j NFQUEUE --queue-num 1")

#Varabili per controllare il pattern del game server. Logica: in FASE0 deve essere fatta la fase0 (registrazione)
FASE0=0 #registrazione
FASE1=1 #inserire username
FASE2=2 #inserire password
FASE3=3 #inserire create poll
FASE4=4 #inserire poll description (flag che scrive)
FASE5=5 #inserire numero per opzioni poll (da questo dipendono le N prossime fasi)
#da aggiungere
FASE_LAST=10 #inserire id della poll
accettati=0
droppati=0

#os.system("iptables -I DOCKER-USER -p tcp --dport 80 -j NFQUEUE --queue-num 1")
#os.system("iptables -I DOCKER-USER -m mark --mark 1 -j ACCEPT")

#Recupero tutte le connessioni utilizzando psutil
#connections=psutil.net_connections()
#Recupero solo le connessioni attive con porta s o d la 12345
#tcp_active_connections = {conn.raddr.port: [FASE0] for conn in connections if conn.status == psutil.CONN_ESTABLISHED and (conn.laddr.port==8080)}

#Come prima cosa richiama la funzione aggiornamento_connessioni(). Parso il pacchetto con scapy, recupero la porta remota e con essa accedo
#al contenuto del dizionario tcp_active_connections() associato ad essa. In base allo stato in cui è la connessione verifico che il
#payload del pacchetto sia quello atteso. In caso affermativo: aggiorno il valore del dizionario con quello successivo, in caso negativo devo 
#terminare la connessione (INVALID o NEW con solo SYN richiesto).
def ispeziona_traffico(packet):
     http_packet = IP(packet.get_payload())
     
     http_packet.show()
     if http_packet.haslayer(Raw) and http_packet.haslayer(TCP):
               print("Pacchetto HTTP")
          #if HTTP in http_packet:
               if http_packet[TCP].dport == 80:
                    load = http_packet[Raw].load
                    print(load)
                    http_total=load.split(b"\r\n\r\n")
                    headers=http_total[0]
                    headers=headers.decode('UTF8','replace')
                    header_fields=headers.split("\n")
                    user_agent=""
                    #pattern="User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0"
                    pattern="python-requests"
                    for header_field in header_fields:
                          #print(header_field)
                          if "User-Agent:" in header_field:
                                user_agent=header_field.strip()
                    if pattern in user_agent:
                         packet.drop()
                         print("Pacchetto droppato")

                    else:
                          packet.set_mark(1)
                          packet.repeat()
                          #http_packet.show()
                          print("pacchetto accettato"+user_agent)
                         
     else:
          packet.accept()
          print("Else")
          print("Pacchetto non riconosciuto HTTP")


nfqueue = NetfilterQueue()
#1 is the iptabels rule queue number, modify is the callback function
nfqueue.bind(1, ispeziona_traffico) 
try:
     nfqueue.run()
except KeyboardInterrupt:
     pass


