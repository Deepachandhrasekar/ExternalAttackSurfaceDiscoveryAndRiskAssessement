import nmap
import socket

def scan_ports(target):
    nm = nmap.PortScanner()

    try:
        # 🔥 Convert domain → IP (VERY IMPORTANT)
        ip = socket.gethostbyname(target)

        nm.scan(
            hosts=ip,
            ports="1-1024",
            arguments="-sT -Pn -T4"
        )

    except Exception as e:
        print(f"Error scanning {target}: {e}")
        return [], {}

    open_ports = []
    services = {}

    print("TARGET:", target)
    print("IP:", ip)
    print("HOSTS FOUND:", nm.all_hosts())

    # 🔥 IMPORTANT FIX: always loop hosts
    for host in nm.all_hosts():
        tcp_data = nm[host].get('tcp', {})

        for port in tcp_data:
            state = tcp_data[port].get("state")

            if state == "open":
                open_ports.append(port)
                services[port] = tcp_data[port].get("name", "unknown")

    print("OPEN PORTS:", open_ports)

    return open_ports, services