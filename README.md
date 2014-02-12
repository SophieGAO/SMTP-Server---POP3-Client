SMTP-Server---POP3-Client
=========================
Basic functions:
SMTP server
Create TCP socket listening on port 25
Receive email from Evolution, Thunderbird, Kmail or others
Forward email to the IP address of destination SMTP server

POP3 client
Connect POP3 server on port 110
Guide user to login and show information about their mails
Display prompt characters such as “mypop >”
Can display content of mails in terminal

Advanced functions (optional):
SMTP server
Authentication with username and password by BASE64 encoding
Automatic resolve the MX record of destination domain
Support SSL

POP3 client
Login with implicit password (replace your password by ****)
Can download mails and save them only on local machine (remove from remote server)
Provide commands set with Linux’s style such as “ls, put, get”
Provide function “display by subject”
Provide function “search text in all mails”
