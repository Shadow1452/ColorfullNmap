import argparse
import nmap
import colorama
from colorama import Fore, Style

# Initialize colorama
colorama.init(autoreset=True)

def run_nmap_scan(target, ports):
    scanner = nmap.PortScanner()
    scanner.scan(target, arguments='-p {}'.format(ports))

    for host in scanner.all_hosts():
        print(Fore.GREEN + f"Host: {host} ({scanner[host].hostname()})")
        print(Fore.YELLOW + "State: %s" % scanner[host].state())

        for proto in scanner[host].all_protocols():
            print(Fore.CYAN + "Protocol: %s" % proto)

            ports = scanner[host][proto].keys()
            for port in ports:
                state = scanner[host][proto][port]['state']
                service = scanner[host][proto][port]['name']
                print(f"Port: {port}\tState: {state}\tService: {service}")


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Colorful Nmap Scanner')
    parser.add_argument('target', help='Target IP address or hostname')
    parser.add_argument('-p', '--ports', default='1-1000', help='Port range to scan (default: 1-1000)')
    args = parser.parse_args()

    run_nmap_scan(args.target, args.ports)
