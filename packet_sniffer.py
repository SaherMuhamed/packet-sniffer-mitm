#!/usr/bin/env python3

import scapy.all as scapy
from scapy.layers import http
from argparse import ArgumentParser
from colorama import Fore
import datetime as dt
import sys
import logging

logging.basicConfig(filename="Access.log", level=logging.INFO, format="%(asctime)s - %(message)s")  # configure logging

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
    # check if the packet contains an HTTP request
    if packet.haslayer(http.HTTPRequest):
        print(
            Fore.RESET + f'{packet[scapy.IP].src} >> {str(packet[scapy.IP].dst)} ─ [{str(dt.datetime.now().strftime("%d/%b/%Y:%H:%M:%S"))}] "{str(packet[http.HTTPRequest].Method, encoding="UTF-8")} ' 
                         f'/{str(packet[http.HTTPRequest].Host, encoding="UTF-8") + str(packet[http.HTTPRequest].Path, encoding="UTF-8")}" {str(packet[http.HTTPRequest].User_Agent, encoding="UTF-8")}' + "\n")

        if packet.haslayer(scapy.Raw):  # check if a packet contains any layers (raw)
            keywords = ['uname', 'username', 'login', 'usr', 'usrname', 'pass', 'email', 'password', 'passwd']
            for keyword in keywords:
                if keyword in str(packet[scapy.Raw].load):
                    print(Fore.YELLOW +
                          f'{packet[scapy.IP].src} >> {str(packet[scapy.IP].dst)} ─ [{str(dt.datetime.now().strftime("%d/%b/%Y:%H:%M:%S"))}] "{str(packet[http.HTTPRequest].Method, encoding="UTF-8")} '
                          f'/{str(packet[http.HTTPRequest].Host, encoding="UTF-8") + str(packet[http.HTTPRequest].Path, encoding="UTF-8")} {str(packet[scapy.Raw].load, encoding="UTF-8")}" {str(packet[http.HTTPRequest].User_Agent, encoding="UTF-8")}' + "\n")
                    logging.critical(
                        msg=f'{packet[scapy.IP].src} >> {str(packet[scapy.IP].dst)} ─ [{str(dt.datetime.now().strftime("%d/%b/%Y:%H:%M:%S"))}] "{str(packet[http.HTTPRequest].Method, encoding="UTF-8")} '
                            f'/{str(packet[http.HTTPRequest].Host, encoding="UTF-8") + str(packet[http.HTTPRequest].Path, encoding="UTF-8")} {str(packet[scapy.Raw].load, encoding="UTF-8")}" {str(packet[http.HTTPRequest].User_Agent, encoding="UTF-8")}')
                    break

    # check if the packet contains an HTTP response
    elif packet.haslayer(http.HTTPResponse):
        print(
            f'{packet[scapy.IP].dst} << {str(packet[scapy.IP].src)} ─ [{str(dt.datetime.now().strftime("%d/%b/%Y:%H:%M:%S"))}]" {packet[http.HTTPResponse].Status_Code.decode() if packet[http.HTTPResponse].Status_Code else "Unknown"} {packet[http.HTTPResponse].Content_Length.decode() if packet[http.HTTPResponse].Content_Length else "Unknown"}' + "\n")


print(f"""
 ____            _        _   ____        _  __  __ 
|  _ \ __ _  ___| | _____| |_/ ___| _ __ (_)/ _|/ _|
| |_) / _` |/ __| |/ / _ \ __\___ \| '_ \| | |_| |_ 
|  __/ (_| | (__|   <  __/ |_ ___) | | | | |  _|  _|   {args().iface} φ
|_|   \__,_|\___|_|\_\___|\__|____/|_| |_|_|_| |_|     {str(dt.datetime.now().strftime("%b %d, %Y %I:%M %p"))}
""")
print('Network packet sniffer, developed and coded by Saher Muhamed - version 1.1.2')
print("────────────────────────────────────────────────────────────────────────────\n")
sniff(interface=args().iface)
