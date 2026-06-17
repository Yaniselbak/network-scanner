import socket
import concurrent.futures

SERVICES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 80: "HTTP", 443: "HTTPS", 3306: "MySQL",
    3389: "RDP", 8080: "HTTP-alt",
}

def grab_banner(s, port):
    try:
        if port in (80, 8080, 443):
            s.send(b"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n")
        banner = s.recv(1024).decode(errors="ignore").strip()
        return banner.split("\n")[0]
    except:
        return None

def scan_port(host, port):
    try:
        s = socket.socket()
        s.settimeout(1)
        s.connect((host, port))
        banner = grab_banner(s, port)
        s.close()
        service = SERVICES.get(port, "Inconnu")
        return port, True, service, banner
    except:
        return port, False, None, None

def scan(host, ports):
    print(f"\n🔍 Scan de {host}\n{'-'*40}")
    ouverts = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
        resultats = executor.map(lambda p: scan_port(host, p), ports)
    for port, ouvert, service, banner in resultats:
        if ouvert:
            print(f"✅ Port {port:5} | {service:10} | {banner or 'pas de bannière'}")
            ouverts.append(port)
    print(f"\n→ {len(ouverts)} port(s) ouvert(s) sur {host}")

scan("192.168.1.254", range(1, 1025))
