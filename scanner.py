#!/usr/bin/env python3
"""
scanner.py — Scanner de ports TCP multithreadé avec détection de bannières.

⚠️ À utiliser uniquement sur des machines dont vous êtes propriétaire
   ou pour lesquelles vous avez une autorisation écrite
   (ex. : localhost, votre lab, scanme.nmap.org).

Exemples :
    python scanner.py scanme.nmap.org
    python scanner.py 127.0.0.1 -p 20-25,80,443,8000-8100
    python scanner.py scanme.nmap.org --top -o resultats.json
"""

import argparse
import concurrent.futures
import csv
import json
import socket
import sys
import time
from datetime import datetime

# Ports les plus courants et leur service habituel
SERVICES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 135: "MSRPC", 139: "NetBIOS", 143: "IMAP",
    443: "HTTPS", 445: "SMB", 993: "IMAPS", 995: "POP3S", 1433: "MSSQL",
    1521: "Oracle", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
    5900: "VNC", 6379: "Redis", 8080: "HTTP-alt", 8443: "HTTPS-alt",
    27017: "MongoDB",
}

# Services considérés comme sensibles s'ils sont exposés
SERVICES_SENSIBLES = {"Telnet", "FTP", "SMB", "RDP", "VNC", "Redis", "MongoDB", "MySQL", "MSSQL", "PostgreSQL"}


def parser_ports(texte):
    """Transforme '22,80,1000-1010' en liste triée de ports."""
    ports = set()
    for morceau in texte.split(","):
        morceau = morceau.strip()
        if "-" in morceau:
            debut, fin = morceau.split("-")
            ports.update(range(int(debut), int(fin) + 1))
        elif morceau:
            ports.add(int(morceau))
    ports_valides = sorted(p for p in ports if 1 <= p <= 65535)
    if not ports_valides:
        raise argparse.ArgumentTypeError("aucun port valide (1-65535)")
    return ports_valides


def recuperer_banniere(sock, hote):
    """Essaie de lire la bannière du service (ex. : 'SSH-2.0-OpenSSH_8.9').

    1. On écoute : certains services (SSH, FTP, SMTP) parlent en premier.
    2. Sinon, on envoie une requête HTTP pour faire répondre un serveur web.
    """
    try:
        banniere = sock.recv(1024)
    except (socket.timeout, OSError):
        banniere = b""
    if not banniere:
        try:
            sock.send(f"HEAD / HTTP/1.0\r\nHost: {hote}\r\n\r\n".encode())
            banniere = sock.recv(1024)
        except (socket.timeout, OSError):
            return None
    texte = banniere.decode(errors="ignore").strip()
    return texte.splitlines()[0] if texte else None


def scanner_port(ip, port, hote, timeout):
    """Retourne un dictionnaire si le port est ouvert, sinon None."""
    try:
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            banniere = recuperer_banniere(sock, hote)
    except (socket.timeout, ConnectionRefusedError, OSError):
        return None
    service = SERVICES.get(port, "Inconnu")
    return {
        "port": port,
        "service": service,
        "banniere": banniere,
        "sensible": service in SERVICES_SENSIBLES,
    }


def sauvegarder(resultats, fichier):
    """Exporte les résultats en JSON ou CSV selon l'extension du fichier."""
    if fichier.endswith(".csv"):
        with open(fichier, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=["port", "service", "banniere", "sensible"])
            writer.writeheader()
            writer.writerows(resultats["ports_ouverts"])
    else:
        with open(fichier, "w", encoding="utf-8") as f:
            json.dump(resultats, f, indent=2, ensure_ascii=False)
    print(f"💾 Résultats enregistrés dans {fichier}")


def main():
    parser = argparse.ArgumentParser(description="Scanner de ports TCP multithreadé")
    parser.add_argument("cible", help="adresse IP ou nom de domaine à scanner")
    parser.add_argument("-p", "--ports", type=parser_ports, default=parser_ports("1-1024"),
                        help="ports à scanner, ex. : 22,80,443 ou 1-1024 (défaut : 1-1024)")
    parser.add_argument("--top", action="store_true",
                        help="scanner uniquement les ports les plus courants")
    parser.add_argument("-t", "--threads", type=int, default=100,
                        help="nombre de threads (défaut : 100)")
    parser.add_argument("--timeout", type=float, default=1.0,
                        help="délai d'attente par port en secondes (défaut : 1)")
    parser.add_argument("-o", "--output", help="fichier de sortie (.json ou .csv)")
    args = parser.parse_args()

    ports = sorted(SERVICES) if args.top else args.ports

    try:
        ip = socket.gethostbyname(args.cible)
    except socket.gaierror:
        sys.exit(f"❌ Impossible de résoudre l'hôte « {args.cible} »")

    print(f"\n🔍 Scan de {args.cible} ({ip}) — {len(ports)} port(s)")
    print("⚠️  Ne scannez que des cibles pour lesquelles vous êtes autorisé.")
    print("-" * 60)

    debut = time.time()
    ouverts = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = [executor.submit(scanner_port, ip, p, args.cible, args.timeout) for p in ports]
        for future in concurrent.futures.as_completed(futures):
            resultat = future.result()
            if resultat:
                ouverts.append(resultat)
    ouverts.sort(key=lambda r: r["port"])
    duree = time.time() - debut

    for r in ouverts:
        alerte = " ⚠️  service sensible exposé" if r["sensible"] else ""
        print(f"✅ Port {r['port']:<5} | {r['service']:<10} | {r['banniere'] or 'pas de bannière'}{alerte}")

    print("-" * 60)
    print(f"→ {len(ouverts)} port(s) ouvert(s) sur {args.cible} en {duree:.1f} s")

    if args.output:
        sauvegarder({
            "cible": args.cible,
            "ip": ip,
            "date": datetime.now().isoformat(timespec="seconds"),
            "duree_secondes": round(duree, 2),
            "ports_scannes": len(ports),
            "ports_ouverts": ouverts,
        }, args.output)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit("\n⛔ Scan interrompu par l'utilisateur")
