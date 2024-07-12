# SQLMap

```bash
sqlmap -u "http://challenge01.root-me.org/web-serveur/ch40/?action=member&member=1" --level=2 --risk=2
```

| Tag            | value                         | Description                                                              |
| -------------- | ----------------------------- | ------------------------------------------------------------------------ |
| **-u**             | URL                           | the target URL                                                           |
| **-p**             | parameter                     | The parameter to test                                                    |
| **--level**        | 1 to 5                        |                                                                          |
| **--risk**         | 1 to 3                        |                                                                          |
| **--random-agent** |                               | Randomize the user-agent                                                 |
| **--dbms**         | string                        | The DBMS tech if known                                                   |
| **--auth-type**    | (Basic, Digest, NTLM or PKI)  | Authentication type                                                      |
| **--auth-creds**   | name:password                 | Authentication credentials                                               |
| **--threads**      | INT                           | Thread number                                                            |
| **--technique**    | UB                            | Use only techniques UNION and BLIND in that order (default "BEUSTQ")<br> |
| **-r**             | file                          | Specify a capured request from Burpsuite                                 |
| **--data**         | "username=\*&password=\*"<br> | Specify post data when dealing with POST request                         |
| **--method**       | PUT                           | Specify the request VERB                                                 |
| **--string**       | "string showed when true"     | Indicate string when injection is successful                             |

# From BurpSuite

1. Capture a request
2. Paste it in a `req.txt` file

```bash
sqlmap -r req.txt
```

# Resources

- https://book.hacktricks.xyz/pentesting-web/sql-injection/sqlmap