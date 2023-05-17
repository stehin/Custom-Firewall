#! /usr/bin/env python3 
from scapy.all import *
from netfilterqueue import NetfilterQueue
import psutil
import os
import time
import binascii
import io
import gzip


#Metto in coda tutte le TCP connections con destinazione e con sorgente la porta del mio servizio
os.system("iptables -A INPUT -p tcp --dport 12345 -m state --state ESTABLISHED -j NFQUEUE --queue-num 1")
os.system("iptables -A INPUT -p tcp --sport 12345 -m state --state ESTABLISHED -j NFQUEUE --queue-num 2")

#Varabili per controllare il pattern del game server. Logica: in FASE0 deve essere fatta la fase0 (registrazione)
FASE0=0 #registrazione
FASE1=1 #inserire username
FASE2=2 #inserire password
FASE3=3 #inserire create poll
FASE4=4 #inserire poll description (flag che scrive)
FASE5=5 #inserire numero per opzioni poll (da questo dipendono le N prossime fasi)
#da aggiungere
FASE_LAST=10 #inserire id della poll


#Recupero tutte le connessioni utilizzando psutil
connections=psutil.net_connections()
#Recupero solo le connessioni attive con porta s o d la 12345
tcp_active_connections = {conn.raddr.port: [FASE0] for conn in connections if conn.status == psutil.CONN_ESTABLISHED and (conn.laddr.port==12345)}

#Aggiorna tcp_active_connections guardando psutil.net_connections(): verifica che le chiavi del dizionario siano
#ancora presenti nelle connessioni ESTABLISHED e aggiunge le nuovi connessioni
def aggiornamento_connessioni():
     return

#Come prima cosa richiama la funzione aggiornamento_connessioni(). Parso il pacchetto con scapy, recupero la porta remota e con essa accedo
#al contenuto del dizionario tcp_active_connections() associato ad essa. In base allo stato in cui è la connessione verifico che il
#payload del pacchetto sia quello atteso. In caso affermativo: aggiorno il valore del dizionario con quello successivo, in caso negativo devo 
#terminare la connessione (INVALID o NEW con solo SYN richiesto).
def ispeziona_traffico(packet):
     return
