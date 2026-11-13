# 🔍 Network Scanner

Deux outils Python de cybersécurité, sans aucune dépendance externe :

| Outil | Rôle | Côté |
|-------|------|------|
| `scanner.py` | Scanner de ports TCP multithreadé avec détection de bannières | 🔴 Offensif (reconnaissance) |
| `log_analyzer.py` | Analyseur de logs Apache/Nginx qui détecte les attaques | 🔵 Défensif (détection) |

L'idée : comprendre une attaque **des deux côtés**, comment un attaquant repère les services exposés et comment un défenseur repère l'attaquant dans ses logs.

> ⚠️ **Usage légal uniquement.** Ne scannez que vos propres machines, votre lab ou des cibles prévues pour ça, comme `scanme.nmap.org`. Scanner un système sans autorisation est illégal.

---

## ⚙️ Installation

```bash
git clone https://github.com/Yaniselbak/network-scanner.git
cd network-scanner
```

Python 3.8+ suffit, aucune bibliothèque à installer.

---

## 🔴 scanner.py : scanner de ports

### Fonctionnalités
- Scan TCP **multithreadé** (100 threads par défaut)
- **Détection de bannières** : version du service (SSH, FTP, HTTP…)
- **Alerte sur les services sensibles** exposés (Telnet, SMB, RDP, bases de données…)
- Choix des ports : liste, plage ou ports les plus courants (`--top`)
- **Export** des résultats en JSON ou CSV

### Utilisation
```bash
# Ports 1 à 1024 (par défaut)
python scanner.py scanme.nmap.org

# Ports précis et plages
python scanner.py 127.0.0.1 -p 22,80,443,8000-8100

# Ports les plus courants + export JSON
python scanner.py scanme.nmap.org --top -o resultats.json
```

| Option | Description | Défaut |
|--------|-------------|--------|
| `-p`, `--ports` | Ports à scanner (`22,80` ou `1-1024`) | `1-1024` |
| `--top` | Uniquement les ports les plus courants | — |
| `-t`, `--threads` | Nombre de threads | `100` |
| `--timeout` | Délai d'attente par port (secondes) | `1` |
| `-o`, `--output` | Fichier de sortie `.json` ou `.csv` | — |

### Exemple de résultat
```
🔍 Scan de scanme.nmap.org (45.33.32.156) — 24 port(s)
⚠️  Ne scannez que des cibles pour lesquelles vous êtes autorisé.
------------------------------------------------------------
✅ Port 22    | SSH        | SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2.13
✅ Port 80    | HTTP       | HTTP/1.1 200 OK
------------------------------------------------------------
→ 2 port(s) ouvert(s) sur scanme.nmap.org en 1.2 s
```

---

## 🔵 log_analyzer.py : détection d'attaques dans les logs

### Ce qu'il détecte
| Attaque | Comment |
|---------|---------|
| 🔨 Force brute | Trop d'échecs `401` / `403` depuis une même IP |
| 📂 Scan de répertoires | Trop d'erreurs `404` depuis une même IP |
| 💉 Injection SQL | Motifs `UNION SELECT`, `' OR '1'='1`… dans l'URL |
| 🧨 XSS | Motifs `<script>`, `onerror=`, `alert(`… dans l'URL |
| 📁 Path traversal | Motifs `../`, `/etc/passwd`… dans l'URL |
| 🤖 Outils d'attaque | `sqlmap`, `nikto`, `gobuster`, `hydra`… dans le User-Agent |

### Utilisation
```bash
# Avec le fichier d'exemple fourni
python log_analyzer.py exemples/access.log

# Sur un vrai fichier, seuils personnalisés + rapport JSON
python log_analyzer.py /var/log/nginx/access.log --seuil-404 10 --seuil-401 5 -o rapport.json
```

| Option | Description | Défaut |
|--------|-------------|--------|
| `--seuil-404` | Nb de `404` pour signaler un scan | `5` |
| `--seuil-401` | Nb de `401`/`403` pour signaler une force brute | `5` |
| `-o`, `--output` | Exporter le rapport en JSON | — |

### Exemple de résultat
```
📋 26 lignes analysées (0 ignorées)
------------------------------------------------------------
🚨 Alertes :
   🔴 [Injection SQL] 203.0.113.42 — /produits.php?id=1' OR '1'='1
   🔴 [XSS] 198.51.100.7 — /recherche?q=<script>alert(1)</script>
   🔴 [Path traversal] 198.51.100.7 — /download?file=../../../../etc/passwd
   🔴 [Scan de répertoires] 192.168.1.10 — 7 erreurs 404
   🔴 [Force brute] 10.0.0.5 — 8 échecs d'authentification
   🔴 [Outil d'attaque détecté] 192.168.1.10 — gobuster
   🔴 [Outil d'attaque détecté] 203.0.113.42 — sqlmap

→ 8 alerte(s), 4 IP suspecte(s)
```

---

## 🧠 Ce que j'ai appris
- Le fonctionnement d'une connexion **TCP** et des **sockets** en Python
- La **programmation concurrente** avec `concurrent.futures` pour accélérer un scan
- Les **expressions régulières** pour analyser des logs
- Les **signatures** des attaques web les plus courantes (OWASP Top 10)

## 🚀 Pistes d'amélioration
- [ ] Scan UDP
- [ ] Détection de la version d'OS
- [ ] Analyse des logs en temps réel (`tail -f`)
- [ ] Alertes par e-mail ou webhook

---

👤 **Yanis El-Bak** — [GitHub](https://github.com/Yaniselbak) · [LinkedIn](https://linkedin.com/in/yanis-el-bak-815996254) · [TryHackMe](https://tryhackme.com/p/yaniselbak)
