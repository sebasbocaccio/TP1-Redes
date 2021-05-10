import scapy.all as scapy
from datetime import datetime
import pickle

capturas = []

# docu: https://scapy.readthedocs.io/en/latest/api/scapy.layers.l2.html?highlight=arp#scapy.layers.l2.ARP

def callback(pkt):
  if pkt.haslayer(scapy.ARP):
    arp = pkt[scapy.ARP]
    captura = [
      datetime.now(),
      "BROADCAST" if pkt[scapy.Ether].dst == "ff:ff:ff:ff:ff:ff" else "UNICAST",
      'how-has' if arp.op == 1 else 'is-at',
      arp.psrc,
      arp.hwsrc,
      arp.pdst,
      arp.hwdst
    ]

    print(captura)
    print()

    capturas.append(captura)

scapy.sniff(prn=callback, count=1000)
print(capturas)
with open('muestra_nodos_distinguidos.pickle', 'wb') as file: pickle.dump(capturas, file)

# para leer
# with open('muestra_nodos_distinguidos.pickle', 'rb') as file:
#   capturas = pickle.load(file)
