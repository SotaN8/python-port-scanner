import os
import socket
import sys
from datetime import datetime
import ipaddress
import time

def scan_port(ip, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((ip, port))
        sock.close()
        return result == 0
    except:
        return False

def get_validated_input(prompt, validator_func, error_message):
    while True:
        try:
            user_input = input(prompt)
            if validator_func(user_input):
                return user_input
            print(error_message)
        except ValueError:
            print(error_message)
        time.sleep(1)

def is_valid_ipv4(ip_address):
    try:
        ipaddress.IPv4Address(ip_address)
        return True
    except ipaddress.AddressValueError:
        return False

def is_valid_port(port_str):
    try:
        port = int(port_str)
        return 1 <= port <= 65535
    except ValueError:
        return False

def main():
    print("""
    ╔════════════════════════════════════════════════════════════════════╗
    ║     ____             __     _____                                  ║
    ║    / __ \____  _____/ /_   / ___/_________ _____  ____  ___  _____ ║
    ║   / /_/ / __ \/ ___/ __/   \__ \/ ___/ __ `/ __ \/ __ \/ _ \/ ___/ ║
    ║  / ____/ /_/ / /  / /_    ___/ / /__/ /_/ / / / / / / /  __/ /     ║
    ║ /_/    \____/_/   \__/   /____/\___/\__,_/_/ /_/_/ /_/\___/_/      ║
    ║                                                                    ║
    ║ Copyright of Nate McGrady, 2025                                    ║
    ║ https://www.nmcgrady.co                                            ║
    ║ https://x.com/natemcgrady                                          ║
    ╚════════════════════════════════════════════════════════════════════╝
    """)

    ip = get_validated_input(
        "Enter an IP address to scan: ",
        is_valid_ipv4,
        "Invalid IP address!"
    )

    start_port = int(get_validated_input(
        "Enter starting port: ",
        is_valid_port,
        "Invalid port range! Please enter a port between 1 and 65535"
    ))

    end_port = int(get_validated_input(
        "Enter ending port: ",
        is_valid_port,
        "Invalid port range! Please enter a port between 1 and 65535"
    ))

    os.system('clear')
    print(f"\nScanning {ip} from port {start_port} to {end_port}")
    print("Scanning started at:", datetime.now().strftime("%H:%M:%S"))

    open_ports = []

    for port in range(start_port, end_port + 1):
        sys.stdout.write(f"\rScanning port {port}")
        sys.stdout.flush()
        if scan_port(ip, port):
            open_ports.append(port)
            
    if open_ports:
        print("\nOpen ports:")
        for port in open_ports:
            try:
                service = socket.getservbyport(port)
                print(f"Port {port}: {service}")
            except:
                print(f"Port {port}: unknown service")
    else:
        print("\nNo open ports found")
    print("\nScan completed at:", datetime.now().strftime("%H:%M:%S"))

if __name__ == "__main__":
    main()
