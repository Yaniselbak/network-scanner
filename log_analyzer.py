#!/usr/bin/env python3
"""
log_analyzer.py — Analyseur de logs Apache/Nginx pour détecter des attaques.

Détecte :
  - les attaques par force brute (trop d'échecs 401/403 par IP)
  - les scans de répertoires (trop d'erreurs 404 par IP)
  - les tentatives d'injection SQL, de XSS et de path traversal dans les URL
  - les outils d'attaque connus dans le User-Agent (sqlmap, nikto, gobuster...)

Exemples :
    python log_analyzer.py exemples/access.log
    python log_analyzer.py /var/log/nginx/access.log --seuil-404 10 -o rapport.json
"""

import argparse
import json
import re
import sys
from collections import Counter, defaultdict
from urllib.parse import unquote

# Format "combined" d'Apache/Nginx :
# IP - - [date] "MÉTHODE URL HTTP/x.x" CODE TAILLE "REFERER" "USER-AGENT"
PATTERN_LOG = re.compile(
    r'(?P<ip>\d{1,3}(?:\.\d{1,3}){3}) \S+ \S+ \[(?P<date>[^\]]+)\] '
    r'"(?P<methode>[A-Z]+) (?P<url>\S+)[^"]*" (?P<code>\d{3})'
    r'(?: \S+ "[^"]*" "(?P<user_agent>[^"]*)")?'
)

# Signatures d'attaques recherchées dans les URL (après décodage)
SIGNATURES = {
    "Injection SQL": re.compile(r"(union\s+select|'\s*or\s*'?1'?\s*=\s*'?1|sleep\(|information_schema|--\s)", re.I),
    "XSS": re.compile(r"(<script|javascript:|onerror\s*=|onload\s*=|alert\()", re.I),
    "Path traversal": re.compile(r"(\.\./|\.\.\\|/etc/passwd|win\.ini)", re.I),
}

OUTILS_ATTAQUE = ["sqlmap", "nikto", "gobuster", "dirbuster", "hydra", "nmap", "wpscan", "masscan", "ffuf"]


def analyser(lignes, seuil_404, seuil_401):
    stats = {"lignes": 0, "lignes_ignorees": 0}
    requetes_par_ip = Counter()
    erreurs_404 = Counter()
    echecs_auth = Counter()
    alertes = []
    outils_vus = defaultdict(set)

    for ligne in lignes:
        ligne = ligne.strip()
        if not ligne:
            continue
        stats["lignes"] += 1
        match = PATTERN_LOG.search(ligne)
        if not match:
            stats["lignes_ignorees"] += 1
            continue

        ip, url, code = match["ip"], unquote(match["url"]), match["code"]
        user_agent = (match["user_agent"] or "").lower()
        requetes_par_ip[ip] += 1

        if code == "404":
            erreurs_404[ip] += 1
        elif code in ("401", "403"):
            echecs_auth[ip] += 1

        for type_attaque, regex in SIGNATURES.items():
            if regex.search(url):
                alertes.append({"type": type_attaque, "ip": ip, "detail": url[:100]})

        for outil in OUTILS_ATTAQUE:
            if outil in user_agent:
                outils_vus[ip].add(outil)

    for ip, nb in erreurs_404.items():
        if nb >= seuil_404:
            alertes.append({"type": "Scan de répertoires", "ip": ip, "detail": f"{nb} erreurs 404"})
    for ip, nb in echecs_auth.items():
        if nb >= seuil_401:
            alertes.append({"type": "Force brute", "ip": ip, "detail": f"{nb} échecs d'authentification"})
    for ip, outils in outils_vus.items():
        alertes.append({"type": "Outil d'attaque détecté", "ip": ip, "detail": ", ".join(sorted(outils))})

    return stats, requetes_par_ip, alertes


def afficher(stats, requetes_par_ip, alertes):
    print(f"\n📋 {stats['lignes']} lignes analysées ({stats['lignes_ignorees']} ignorées)")
    print("-" * 60)
    print("🌐 Top 5 des IP les plus actives :")
    for ip, nb in requetes_par_ip.most_common(5):
        print(f"   {ip:<15} → {nb} requête(s)")

    print("\n🚨 Alertes :")
    if not alertes:
        print("   ✅ Aucune activité suspecte détectée")
        return
    for a in alertes:
        print(f"   🔴 [{a['type']}] {a['ip']} — {a['detail']}")

    ips_suspectes = sorted({a["ip"] for a in alertes})
    print(f"\n→ {len(alertes)} alerte(s), {len(ips_suspectes)} IP suspecte(s) : {', '.join(ips_suspectes)}")


def main():
    parser = argparse.ArgumentParser(description="Analyseur de logs Apache/Nginx")
    parser.add_argument("fichier", help="chemin du fichier de logs (ex. : access.log)")
    parser.add_argument("--seuil-404", type=int, default=5,
                        help="nb d'erreurs 404 pour signaler un scan (défaut : 5)")
    parser.add_argument("--seuil-401", type=int, default=5,
                        help="nb d'échecs 401/403 pour signaler une force brute (défaut : 5)")
    parser.add_argument("-o", "--output", help="exporter le rapport en JSON")
    args = parser.parse_args()

    try:
        with open(args.fichier, encoding="utf-8", errors="ignore") as f:
            stats, requetes_par_ip, alertes = analyser(f, args.seuil_404, args.seuil_401)
    except FileNotFoundError:
        sys.exit(f"❌ Fichier introuvable : {args.fichier}")

    afficher(stats, requetes_par_ip, alertes)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump({"statistiques": stats, "alertes": alertes}, f, indent=2, ensure_ascii=False)
        print(f"💾 Rapport enregistré dans {args.output}")


if __name__ == "__main__":
    main()
