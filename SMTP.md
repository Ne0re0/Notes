
### Basic connection
```bash
nc -vn IP 25
```

### Basic usage (nc/telnet)
```bash
helo DOMAIN                 # Tells the server to join the domain
MAIL FROM:source@localhost  # Set the source
RCPT TO:recipient@localhost # Set the recipient
DATA
Subject: The subject of the email
here comes the content
.                           # Do not forget the dot
QUIT                        # To quit and send the email
```