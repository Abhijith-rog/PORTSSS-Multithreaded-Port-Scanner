import pyfiglet
import socket
import sys
from datetime import datetime
import threading
import csv
from scapy.all import IP, UDP, ICMP, sr1
from tqdm import tqdm

ascii_banner = pyfiglet.figlet_format("PORTSSS")
print(ascii_banner)

#argument 

if len(sys.argv) == 2:
    try:
        target = socket.gethostbyname(sys.argv[1])
    except socket.gaierror:
        print(f"\nHostname '{sys.argv[1]}' could not be resolved.")
        sys.exit()
else:
    print("usage: python3 PORTSS.py <hostname>")
    sys.exit()
    
output_file = f"scan_results_{target}.csv"

#banner

print("-" * 60)
print(f"scanning Target: {target}")
print(f"Scan started at: {datetime.now()}")
print("-" * 60)

print_lock = threading.Lock()
scan_results = []

#TCP scan
def scan_tcp_port(port):
    protocol_probes = {
        21:b'\r\n',        #FTP
        22:b'\r\n',        #SSH
        23:b'\r\n',        #Telnet
        25:b'EHLO example.com\r\n',    #SMTP
        80:b'HEAD / HTTP/1.1\r\nHost: localhost\r\n\r\n',   #HTTP
        110:b'\r\n',       #pop3
        143:b'\r\n',       #IMAP
        443:b'HEAD / HTTP/1.1\r\nHost: localhost\r\n\r\n', #HTTPS
        3306:b'\r\n',      #MySQL
        3389:b'\r\n',      #RDP
        8080:b'HEAD / HTTP/1.1\r\nHost:localhost\r\n\r\n', #HTTP alternate
         
    }
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(3)
            result = s.connect_ex((target, port))
            if result == 0:
                try:
                    service = socket.getservbyport(port, 'tcp')
                except OSError:
                    service = "Unknown"
                    
                try:
                    #genric(not assuming http)
                    probe = protocol_probes.get(port, b'\r\n')
                    s.sendall(probe)
                    banner = s.recv(1024).decode(errors='ignore').strip().split("\n") [0]
                except:
                    banner = "No banner"
                with print_lock:
                    print(f"[TCP] port {port} is open\tService: {service.upper()}\tBanner: {banner}")
                    scan_results.append((port, 'TCP',service.upper(),banner))
    except:
        pass
    
    
#UDP scan

def scan_udp_port(port):
    try:
        
        #sending UDP pasket using scapy
        pkt = IP(dst=target)/UDP(dport=port)/b'hello'
        response = sr1(pkt, timeout=3, verbose=0)
        
        if response is None:
            result = "No response (open|filtered)"
        elif response.haslayer(ICMP):
            icmp_type = response.getlayer(ICMP).type
            icmp_code = response.getlayer(ICMP).code
            if icmp_type == 3 and icmp_code == 3:
                result = "Closed (ICMP port unreachable)"
            else:
                result = f"ICMP type {icmp_type}, code {icmp_code} (filtered)"
        else:
            result = "UDP response received (open)"
            
            #Attempt to identify service
            try:
                service = socket.getservbyport(port, 'udp')
            except OSError:
                service = "unkown"
                
            with print_lock:
                print(f"[UDP] Port {port}: {result}\tService: {service.upper()}")
                scan_results.append((port, 'UDP', service.upper(), result))
    except Exception as e:
        with print_lock:
            print(f"[UDP] port {port}: Error - {e}")
            
#Threading for both TCP and UDP

MAX_CONCURRENT_THREADS = 500 #can tune this
semaphore = threading.BoundedSemaphore(value=MAX_CONCURRENT_THREADS)

def thread_scan_tcp(start=1, end=100):
    threads = []
    port_range = range(start, end + 1)
    pbar = tqdm(total=len(port_range), desc="Scanning TCP Ports", ncols=100)
    
    def thread_target(port):
        with semaphore:
            scan_tcp_port(port)
            pbar.update(1)
    
    for port in range(start, end + 1):
        t = threading.Thread(target=thread_target, args=(port,))
        threads.append(t)
        t.start()
        
    for t in threads:
        t.join()
    pbar.close()
        
def thread_scan_udp(start=1, end=100):
    threads = []
    port_range = range(start, end + 1)
    pbar = tqdm(total=len(port_range), desc="scanning UDP Ports", ncols=100)
    
    
    def thread_target(port):
        with semaphore:
            scan_udp_port(port)
            pbar.update(1)
            
    for port in range(start, end + 1):
        t = threading.Thread(target=thread_target, args=(port,))
        threads.append(t)
        t.start()
    for t in threads:
        t.join()
    pbar.close()
    
    
    
#main execution

try:
    thread_scan_tcp(start=1, end=65535) #scan TCP ports 1-100
    thread_scan_udp(start=1, end=65535) #scan UDP ports 1-100
    
    #cli OUTPUT
    
    print("\n" + "+"*60)
    print("RESULT")
    print("="*60)
    print(f"Host: {target}")
    print(f"Scan completed at: {datetime.now()}")
    print("-" * 60)
    print("{:<9} {:<13} {:<12} {}".format("PORT", "STATE", "SERVICE", "BANNER/RESPONSE"))
    print("-" * 60)

    for result in sorted(scan_results, key=lambda x: (x[0], x[1])):
        port, proto, service, banner = result
        state = "open" if "open" in banner.lower() or "response" in banner.lower() else "open|filterd"
        print("{:<9} {:<13} {:<12} {}".format(f"{port}/{proto.lower()}",state, service.lower(), banner))
    
    
    #Save to CSV
    
    with open(output_file, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(['Port', 'Protocol', 'Service','Banner?Response'])
        writer.writerows(scan_results)
    print(f"\nScan Completed at: {datetime.now()}")
    print(f"Result saved tp : {output_file}")

except KeyboardInterrupt:
    print("\nScan Interrupted by user.")
    sys.exit()
except socket.gaierror:
    print("\nHostname could not be resolved.")
    sys.exit()
except socket.error:
    print("\nServer not responding.")
    sys.exit()    


