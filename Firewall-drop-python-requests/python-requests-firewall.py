#! /usr/bin/env python3

# Per il corretto funzionamento del firewall custom è necessario installare:
#   sudo apt install libnfnetlink-dev libnetfilter-queue-dev

from scapy.all import *
from netfilterqueue import NetfilterQueue
import os

# Metto in coda tutte le TCP connections con destinazione la porta 80
# L'idea è quella di avere le seguenti regole nella chain DOCKER-USER di iptables:
#    1) Se il pacchetto ha porta destinazione 80 e non è marcato con 1 viene messo in una coda per essere ispezionato
#       dallo script
#    2) Altrimenti, viene fatto il RETURN alla chain precedente (unica regola già presente in DOCKER-USER)
# La regola viene messa in cima all'interno della chain

os.system("/usr/sbin/iptables -I DOCKER-USER -p tcp --dport 80 -m mark ! --mark 1 -j NFQUEUE --queue-num 1")


# Questa funzione verifica se il pacchetto è TCP e che trasporti dei dati, in questo caso si assicura che sia
# un pacchetto destinato alla porta 80. In tal caso si procede a verificare che negli header del pacchetto,
# presunto HTTP, ci sia nello User-Agent la stringa 'python-request'. Se questi check vengono superati allora è
# un presunto attacco e quindi il pacchetto viene droppato. In tutti gli altri casi, il pacchetto viene marcato
# con 1 per poi essere rimesso all'inizio della chain, lo scopo è poi far continuare la valutazione delle regole
# di iptables così da lasciare la decisione al firewall del sistema operativo.
def ispeziona_traffico(packet):
    http_packet = IP(packet.get_payload())

    http_packet.show()
    if http_packet.haslayer(Raw) and http_packet.haslayer(TCP):
        print("Pacchetto HTTP")
        # if HTTP in http_packet:
        if http_packet[TCP].dport == 80:
            load = http_packet[Raw].load
            print(load)
            http_total = load.split(b"\r\n\r\n")
            headers = http_total[0]
            headers = headers.decode('UTF8', 'replace')
            header_fields = headers.split("\n")
            user_agent = ""
            # pattern="User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0"
            pattern = "python-requests"
            for header_field in header_fields:
                # print(header_field)
                if "User-Agent:" in header_field:
                    user_agent = header_field.strip()

            if pattern in user_agent:
                packet.drop()
                print("Pacchetto droppato")
            else:
                # Marca il pacchetto con 1 richiede l'esecuizione delle regole nella chain
                packet.set_mark(1)
                packet.repeat()
                # http_packet.show()
                print("pacchetto accettato" + user_agent)
        else:
            # Marca il pacchetto con 1 richiede l'esecuizione delle regole nella chain
            packet.set_mark(1)
            packet.repeat()

    else:
        # Marca il pacchetto con 1 richiede l'esecuizione delle regole nella chain
        # packet.accept()
        packet.set_mark(1)
        packet.repeat()
        print("Else")
        print("Pacchetto non trasporta dati o non è TCP")


def main():
    nfqueue = NetfilterQueue()
    # 1 is the iptabels rule queue number, modify is the callback function
    nfqueue.bind(1, ispeziona_traffico)
    try:
        nfqueue.run()
    except KeyboardInterrupt:
        print('\nClearing iptables...')
        os.system("/usr/sbin/iptables -D DOCKER-USER -p tcp --dport 80 -m mark ! --mark 1 -j NFQUEUE --queue-num 1")
        print('Done!')


if __name__ == '__main__':
    main()
