import argparse
import nmap
import colorama
from colorama import Fore, Style
from tqdm import tqdm
import threading
import sys
import time
import keyboard

# Initialize Colorama
colorama.init(autoreset=True)

def display_progress_bar(total_ports):
    # Display the progress bar
    with tqdm(total=total_ports, unit='port', ncols=80) as progress_bar:
        while display_progress:
            progress_bar.update(1)
            time.sleep(0.1)

def run_nmap_scan(target, ports, disable_ping, show_version):
    scanner = nmap.PortScanner()
    arguments = '-p {} {} {}'.format(ports, '-Pn' if disable_ping else '', '-sV' if show_version else '')  # Add -sV to show version if enabled
    scanner.scan(target, arguments=arguments)

    print(Fore.YELLOW + "Scanning target: {}".format(target))
    print()

    total_ports = sum(len(scanner[host][proto]) for host in scanner.all_hosts() for proto in scanner[host])

    # Create a separate thread to display the progress bar
    progress_thread = threading.Thread(target=display_progress_bar, args=(total_ports,))
    progress_thread.start()

    for host in scanner.all_hosts():
        print(Fore.GREEN + "Host: {} ({})".format(host, scanner[host].hostname()))
        print(Fore.YELLOW + "State: %s" % scanner[host].state())

        for proto in scanner[host].all_protocols():
            print(Fore.CYAN + "Protocol: %s" % proto)

            ports = scanner[host][proto].keys()
            for port in ports:
                port_info = scanner[host][proto][port]
                state = port_info['state']
                service = port_info['name']
                version = port_info['version'] if show_version else None

                print(Fore.WHITE + "  Port: {}".format(port))
                print(Fore.WHITE + "    State: {}".format(state))
                print(Fore.WHITE + "    Service: {}".format(service))
                if version:
                    print(Fore.WHITE + "    Version: {}".format(version))
                print()

    # Stop the progress bar thread
    global display_progress
    display_progress = False
    progress_thread.join()

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Colorful Nmap Scanner', formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument('target', help='Target IP address or hostname')
    parser.add_argument('-p', '--ports', default='1-1000', help='Port range to scan (default: 1-1000)')
    parser.add_argument('-Pn', dest='disable_ping', action='store_true', help='Block ping probes')
    parser.add_argument('-sV', dest='show_version', action='store_true', help='Show version of found ports')
    parser.add_argument('--version', action='version', version='%(prog)s 1.0', help='Show the version number and exit')
    args = parser.parse_args()

    # Check if the arrow-up key is pressed to display the progress bar
    if sys.stdin.isatty():
        try:
            if sys.stdin.fileno() == 0:
                keyboard_thread = threading.Thread(target=keyboard.is_pressed, args=('up',))
                keyboard_thread.start()
                while not keyboard_thread.is_alive():
                    pass
                while not keyboard_thread.is_set():
                    time.sleep(0.1)
                display_progress = True
        except Exception:
            pass

    run_nmap_scan(args.target, args.ports, args.disable_ping, args.show_version)
