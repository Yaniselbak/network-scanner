import re
from collections import Counter

# ---- Fichier de log simulé ----
# Format Apache/Nginx classique
LOGS = """
192.168.1.10 - - [17/Jun/2026:08:12:01] "GET /index.html HTTP/1.1" 200
192.168.1.10 - - [17/Jun/2026:08:12:05] "GET /admin HTTP/1.1" 404
192.168.1.10 - - [17/Jun/2026:08:12:06] "GET /admin HTTP/1.1" 404
192.168.1.10 - - [17/Jun/2026:08:12:07] "GET /admin HTTP/1.1" 404
10.0.0.5 - - [17/Jun/2026:08:15:00] "POST /login HTTP/1.1" 401
10.0.0.5 - - [17/Jun/2026:08:15:01] "POST /login HTTP/1.1" 401
10.0.0.5 - - [17/Jun/2026:08:15:02] "POST /login HTTP/1.1" 401
10.0.0.5 - - [17/Jun/2026:08:15:03] "POST /login HTTP/1.1" 401
10.0.0.5 - - [17/Jun/2026:08:15:04] "POST /login HTTP/1.1" 401
203.0.113.42 - - [17/Jun/2026:09:00:00] "GET /index.html HTTP/1.1" 200
203.0.113.42 - - [17/Jun/2026:09:00:01] "GET /secret HTTP/1.1" 403
"""


SEUIL_404 = 3   # Plus de 3 erreurs 404 = scan de répertoires
SEUIL_401 = 3   # Plus de 3 échecs login = brute force

def analyser_logs(logs):
    lignes = logs.strip().split("\n")
    
    # Extraire IP, code HTTP et URL
    pattern = r'(\d+\.\d+\.\d+\.\d+).+"(\w+) (.+?) HTTP.+" (\d+)'
    
    erreurs_404 = Counter()
    erreurs_401 = Counter()
    toutes_ips = Counter()
    
    print(f"\n📋 Analyse de {len(lignes)} lignes de logs\n{'-'*45}")
    
    for ligne in lignes:
        match = re.search(pattern, ligne)
        if match:
            ip = match.group(1)
            methode = match.group(2)
            url = match.group(3)
            code = match.group(4)
            
            toutes_ips[ip] += 1
            
            if code == "404":
                erreurs_404[ip] += 1
            elif code == "401":
                erreurs_401[ip] += 1
    
    
    print("🌐 Activité par IP :")
    for ip, count in toutes_ips.most_common():
        print(f"  {ip:15} → {count} requête(s)")
    
    print("\n🚨 Alertes détectées :")
    alerte = False
    
    for ip, count in erreurs_404.items():
        if count >= SEUIL_404:
            print(f"  ⚠️  Scan de répertoires détecté — {ip} ({count} erreurs 404)")
            alerte = True
    
    for ip, count in erreurs_401.items():
        if count >= SEUIL_401:
            print(f"  🔴 Brute force détecté — {ip} ({count} tentatives de login)")
            alerte = True
    
    if not alerte:
        print("  ✅ Aucune activité suspecte détectée")

analyser_logs(LOGS)
