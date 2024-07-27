import socket
from ipaddress import ip_network, AddressValueError
from threading import Thread, Lock

# Function for scanning range of IP addresses and finding active devices
def scan_ip_range(network):
    active_ips = []
    threads = []
    lock = Lock()  # Lock to manage access to shared list

    try:
        for ip in ip_network(network).hosts():
            t = Thread(target=check_ip, args=(str(ip), active_ips, lock))
            threads.append(t)
            t.start()

        for t in threads:
            t.join()

    except ValueError as e:
        print(f"Invalid network address: {e}")
    
    return active_ips

def check_ip(ip, active_ips, lock):
    try:
        print(f"Checking IP: {ip}")  # Debug: check which IP is being checked
        socket.gethostbyaddr(ip)
        with lock:
            active_ips.append(ip)
    except socket.herror:
        print(f"IP not found: {ip}")  # Debug: IP not found
        pass

# Function to scan open ports on a specific IP address
def scan_ports(ip, port_range):
    open_ports = []
    threads = []
    lock = Lock()  # Lock to manage access to shared list

    for port in port_range:
        t = Thread(target=check_port, args=(ip, port, open_ports, lock))
        threads.append(t)
        t.start()

    for t in threads:
        t.join()

    return open_ports

def check_port(ip, port, open_ports, lock):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(1)
    result = sock.connect_ex((ip, port))
    if result == 0:
        print(f"Port open: {port} on IP: {ip}")  # Debug: port is open
        with lock:
            open_ports.append(port)
    else:
        print(f"Port closed: {port} on IP: {ip}")  # Debug: port is closed
    sock.close()

# Main function which combines IP addresses range and port scanning
def main(network, port_range):
    active_ips = scan_ip_range(network)
    for ip in active_ips:
        open_ports = scan_ports(ip, port_range)
        print(f"Active IP: {ip}\nOpen Ports: {open_ports}")

if __name__ == "__main__":
    network = input("Input network to scan (In CIDR format example>192.168.1.0/24): ")
    port_range = range(20, 1025)
    main(network, port_range)
   
