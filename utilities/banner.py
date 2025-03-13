from colorama import Fore, Style


def print_banner():
    print(Fore.CYAN + Style.BRIGHT + """
    ██╗  ██╗████████╗████████╗██████╗     ███████╗███╗   ██╗██╗███████╗███████╗
    ██║  ██║╚══██╔══╝╚══██╔══╝██╔══██╗    ██╔════╝████╗  ██║██║██╔════╝██╔════╝
    ███████║   ██║      ██║   ██████╔╝    ███████╗██╔██╗ ██║██║█████╗  █████╗  
    ██╔══██║   ██║      ██║   ██╔═══╝     ╚════██║██║╚██╗██║██║██╔══╝  ██╔══╝  
    ██║  ██║   ██║      ██║   ██║         ███████║██║ ╚████║██║██║     ██║     
    ╚═╝  ╚═╝   ╚═╝      ╚═╝   ╚═╝         ╚══════╝╚═╝  ╚═══╝╚═╝╚═╝     ╚═╝     
                     Packet Sniffer Tool | Version 2.1.0                                                      
    """ + Style.RESET_ALL)

    print(Fore.YELLOW + Style.BRIGHT + "───────────────────────────────────────────────────────────────────────────────" + Style.RESET_ALL)
    print(Fore.YELLOW + Style.BRIGHT + "  Author  : Saher Muhamed" + Style.RESET_ALL)
    print(Fore.YELLOW + Style.BRIGHT + "  Github  : https://github.com/SaherMuhamed/packet-sniffer-mitm" + Style.RESET_ALL)
    print(Fore.YELLOW + Style.BRIGHT + "───────────────────────────────────────────────────────────────────────────────" + Style.RESET_ALL)
