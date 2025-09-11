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

