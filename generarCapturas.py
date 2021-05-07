#!/usr/bin/env python3
from scapy.all import *
from scapy.layers.l2 import Ether
import numpy as np
import pandas as pd
import os
from datetime import datetime

S1 = {}
data = {}

def mostrar_fuente(S):
    N = sum(S.values())
    simbolos = sorted(S.items(), key=lambda x: -x[1])
    print("S: ")
    print("\n".join([ " %s : %.5f - I: %.5f" % (d,k/N,- math.log(k/N,2)) for d,k in simbolos ]))
    H = - math.fsum([(k/N * math.log(k/N,2)) for d,k in simbolos ])
    print("H(S): %.5f" %  H )

def callback(pkt):
    if pkt.haslayer(Ether):
        dire = "BROADCAST" if pkt[Ether].dst=="ff:ff:ff:ff:ff:ff" else "UNICAST"
        
        #s_i = (dire, proto) # Aca se define el simbolo de la fuente
        # s_i = dire 

        proto = pkt[Ether].type # El campo type del frame tiene el protocolo
        s_i = dire + " ("+str(proto)+")"
        if s_i not in S1:
            S1[s_i] = 0.0

        S1[s_i] += 1.0
        S2 = S1.copy()
        data[datetime.now()] = S2.values()


sniff(prn=callback, count=100)

mostrar_fuente(S1)

df = pd.DataFrame.from_dict(data, orient='index', columns=S1.keys())
df = df.fillna(0)
df.to_csv('capturas.csv')
