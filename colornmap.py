import argparse
import nmap
import colorama
from colorama import Fore, Style
from tqdm import tqdm

# Initialize colorama
colorama.init(autoreset=True)

def run_nmap_scan(target, ports, disable_ping, show_version):
    scanner = nmap.PortScanner()
    arguments = '-p {} {} {}'.format(ports, '-Pn' if disable_ping else '', '-sV' if show_version else '')  # Add -sV to show version if enabled
    scanner.scan(target, arguments=arguments)

    print(Fore.YELLOW + "Scanning target: {}".format(target))
    print()

    total_ports = sum(len(scanner[host][proto]) for host in scanner.all_hosts() for proto in scanner[host])
    progress_bar = tqdm(total=total_ports, unit='port', ncols=80)

    for host in scanner.all_hosts():
        print(Fore.GREEN + f"Host: {host} ({scanner[host].hostname()})")
        print(Fore.YELLOW + "State: %s" % scanner[host].state())

        for proto in scanner[host].all_protocols():
            print(Fore.CYAN + "Protocol: %s" % proto)

            ports = scanner[host][proto].keys()
            for port in ports:
                state = scanner[host][proto][port]['state']
                service = scanner[host][proto][port]['name']
                if show_version:
                    version = scanner[host][proto][port]['version']
                    if version:
                        print(Fore.WHITE + f"  Port: {port}")
                        print(Fore.WHITE + "    State: {}".format(state))
                        print(Fore.WHITE + "    Service: {}".format(service))
                        print(Fore.WHITE + "    Version: {}".format(version))
                        print()
                    else:
                        print(Fore.WHITE + f"  Port: {port}")
                        print(Fore.WHITE + "    State: {}".format(state))
                        print(Fore.WHITE + "    Service: {}".format(service))
                        print()
                else:
                    print(Fore.WHITE + f"  Port: {port}")
                    print(Fore.WHITE + "    State: {}".format(state))
                    print(Fore.WHITE + "    Service: {}".format(service))
                    print()

                progress_bar.update(1)
    progress_bar.close()

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Colorful Nmap Scanner', formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument('target', help='Target IP address or hostname')
    parser.add_argument('-p', '--ports', default='1-1000', help='Port range to scan (default: 1-1000)')
    parser.add_argument('-Pn', dest='disable_ping', action='store_true', help='Block ping probes')
    parser.add_argument('-sV', dest='show_version', action='store_true', help='Show version of found ports')
    parser.add_argument('--version', action='version', version='%(prog)s 2.0.1', help='Show the version number and exit')
    args = parser.parse_args()

    run_nmap_scan(args.target, args.ports, args.disable_ping, args.show_version)
