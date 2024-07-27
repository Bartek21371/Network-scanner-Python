import socket
from ipaddress import ip_network 
from threading import Thread

# Function for scan range of IP addresses and find active devices

def scan_ip_range(network):
    active_ips = []
    for ip in ip_network(network).hosts:
        t = Thread(target=check_ip, args=(str(ip), active_ips))
        t.start()
    return active_ips

def check_ip(ip, active_ips):
    try:
        socket.gethostbyaddr(ip)
        active_ips.append(ip)
    except socket.herror:
        pass

# Function to scan open ports on a specific IP address

def scan_ports(ip, port_range):
    open_ports = []
    for port in port_range:
        t = Thread(target=check_port, args=(ip, port, open_ports))
        t.start()
    return open_ports

def check_port(ip, port, open_ports):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(1)
    result = sock.connect_ex((ip, port))
    if result == 0:
        open_ports.append(port)
    sock.close()
    
# Main function which combine IP addresses range and port scanning 

def main(network, port_range):
    active_ips = []
    for ip in active_ips:
        open_ports = scan_ports(ip, port_range)
        print(f"Active IP: {ip}\n Open Ports: {open_ports}")

if __name__ == "__main__":
    network = input("Input network to scan (In CIDR format example>192.168.1.0/24): ")
    port_range = range(20, 1025)
    main(network, port_range)