#!/usr/bin/env python3

import scapy.all as scapy
from scapy.layers import http
from argparse import ArgumentParser
from colorama import Fore
import datetime as dt
import sys

if sys.version_info < (3, 0):
    sys.stderr.write("\nYou need python 3.0 or later to run this script\n")
    sys.stderr.write("Please update and make sure you use the command python3 packet_sniffer.py -i <interface>\n\n")
    sys.exit(0)


def args():
    parser = ArgumentParser(description="------- Simple Tool to Sniffing Packets through an Interface -------")
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
        print(Fore.RESET + "Requested from: " + packet[scapy.IP].src)
        # print(packet.show())
        url = packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path
        print(Fore.RESET + "User-Agent: " + str(packet[http.HTTPRequest].User_Agent, encoding="UTF-8"))
        print(Fore.RESET + "URL: " + str(packet[http.HTTPRequest].Method, encoding="UTF-8") + " - " + 
              str(url, encoding="UTF-8") + " is at " + str(packet[scapy.IP].dst))

        if packet.haslayer(scapy.Raw):  # check if a packet contains any layers (raw)
            load = str(packet[scapy.Raw].load)
            keywords = ['uname', 'username', 'login', 'usr', 'usrname', 'pass', 'email', 'password', 'passwd']
            for keyword in keywords:
                if keyword in load:
                    print(Fore.YELLOW + "\n[+] Possible credentials ==> " + load + "\n")
                    break
        print("\n\n")


print('\nNetwork packet sniffer, developed and coded by Saher Muhamed - version 1.0.1\n')
print("==========================")
print("* " + str(dt.datetime.now().strftime("%b %d, %Y %H:%M:%S %p")))
print("* start sniffing on " + args().iface)
print("==========================\n")
sniff(interface=args().iface)
