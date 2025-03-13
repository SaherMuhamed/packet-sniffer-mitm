#!/usr/bin/env python3

import sys
import signal
import logging

import datetime as dt
import scapy.all as scapy
from scapy.layers import http
from argparse import ArgumentParser
from utilities.banner import print_banner
from colorama import Fore, Style, init

init(autoreset=True)  # initialize colorama
logging.basicConfig(
    filename="Sniffing.log",
    level=logging.INFO,
    format="%(asctime)s - %(message)s",
    datefmt="%d/%b/%Y %I:%M:%S %p"
)

if sys.version_info < (3, 0):
    sys.stderr.write("\nYou need Python 3.0 or later to run this script\n")
    sys.stderr.write("Please update and use the command: python3 packet_sniffer.py -i <interface>\n\n")
    sys.exit(0)

quiet_mode = False
verbose_mode = False


def user_interrupt_handler(sig, frame):
    """Handle Ctrl+C to stop sniffing."""
    print(Fore.RED + "\n[!] Sniffing stopped. Exiting...\n" + Style.RESET_ALL)
    logging.info("Sniffing stopped by user.")
    sys.exit(0)


def args():
    """Function to get user arguments from terminal."""
    parser = ArgumentParser(description="------- Advanced Packet Sniffer Tool -------")
    parser.add_argument('-i', '--interface', dest='iface', required=True,
                        help='Specify the network interface (e.g., wlan0)')
    parser.add_argument('-f', '--filter', dest='filter', default="tcp port 80",
                        help='Specify packet type to filter (e.g., http, tcp, udp)')
    parser.add_argument('-c', '--count', dest='count', type=int, default=0,
                        help='Number of packets to capture (0 for unlimited)')
    parser.add_argument('-q', '--quiet', dest='quiet', action='store_true',
                        help='Enable quiet mode (suppress console output)')
    parser.add_argument('-v', '--verbose', dest='verbose', action='store_true',
                        help='Enable verbose mode (show detailed output)')
    options = parser.parse_args()

    if not options.iface:
        parser.error("[-] Please specify a valid interface card, e.g., --interface wlan0")

    return options


def sniff(interface, packet_filter, packet_count_limit):
    """Sniff packets on the specified interface."""
    print_banner()
    print(Fore.GREEN + f"[+] Starting packet sniffing on interface [{interface}]..." + Style.RESET_ALL)
    logging.info(f"Started sniffing on interface {interface} with filter '{packet_filter}'")

    try:
        scapy.sniff(
            iface=interface,
            store=False,  # store=False that tells scapy do not store flowing packets in memory so
            # that it doesn't cause too much pressure on our machine
            prn=process_sniffed_packet,
            filter=packet_filter,
            count=packet_count_limit
        )
    except PermissionError:
        print(Fore.RED + "[!] You need root privileges to sniff packets. Try running with sudo." + Style.RESET_ALL)
        logging.error("Permission denied. Root privileges required.")
        sys.exit(1)
    except Exception as e:
        print(Fore.RED + f"[!] An error occurred: {e}" + Style.RESET_ALL)
        logging.error(f"Error: {e}")
        sys.exit(1)


def process_sniffed_packet(packet):
    """Process each sniffed packet."""
    global quiet_mode, verbose_mode

    if packet.haslayer(http.HTTPRequest):
        http_request = packet[http.HTTPRequest]
        src_ip = packet[scapy.IP].src
        method = str(http_request.Method, encoding="UTF-8")
        host = str(http_request.Host, encoding="UTF-8")
        path = str(http_request.Path, encoding="UTF-8")
        user_agent = str(http_request.User_Agent, encoding="UTF-8")
        timestamp = dt.datetime.now().strftime("%d/%b/%Y %I:%M:%S %p")

        # log HTTP request
        log_message = f'{src_ip} ─ [{timestamp}] "{method} {host}{path}" {user_agent}'
        if not quiet_mode:
            print(f"{log_message}\n" + Style.RESET_ALL)
        logging.info(log_message)

        if packet.haslayer(scapy.Raw):  # check if a packet contains any layers (raw)
            raw_load = str(packet[scapy.Raw].load)
            keywords = ['uname', 'username', 'login', 'usr', 'pass', 'email', 'password', 'passwd']
            for keyword in keywords:
                if keyword in raw_load:  # check for sensitive data in raw layer
                    sensitive_log = f'{src_ip} ─ [{timestamp}] "{method} {host}{path}" {user_agent} {raw_load}'
                    if not quiet_mode:
                        print(Fore.RED + f"[Sensitive Data] {sensitive_log}\n" + Style.RESET_ALL)
                    logging.critical(sensitive_log)
                    break

    if verbose_mode and not quiet_mode:
        print(Fore.MAGENTA + f"[Verbose] Packet Details:\n{packet.show(dump=True)}" + Style.RESET_ALL)


if __name__ == "__main__":
    signal.signal(signal.SIGINT, user_interrupt_handler)
    options = args()
    quiet_mode = options.quiet
    verbose_mode = options.verbose
    sniff(interface=options.iface, packet_filter=options.filter, packet_count_limit=options.count)
