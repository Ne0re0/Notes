
Here will be a bunch of stuff that I don't know where to insert


# Lsof

- lsof is a powershell tool to identify opened files and their network connection

```bash
sudo lsof -i :NUMERIC_PORT_VALUE_HERE
sudo lsof -i :80 # example
```

# Nip.io

[nip.io](https://nip.io/) allows you to do that by mapping any IP Address to a hostname using the following formats:

Without a name:
- `10.0.0.1.nip.io` maps to `10.0.0.1`
- `192-168-1-250.nip.io` maps to `192.168.1.250`
- `0a000803.nip.io` maps to `10.0.8.3`

With a name:
- `app.10.8.0.1.nip.io` maps to `10.8.0.1`
- `app-116-203-255-68.nip.io` maps to `116.203.255.68`
- `app-c0a801fc.nip.io` maps to `192.168.1.252`
- `customer1.app.10.0.0.1.nip.io` maps to `10.0.0.1`
- `customer2-app-127-0-0-1.nip.io` maps to `127.0.0.1`
- `customer3-app-7f000101.nip.io` maps to `127.0.1.1`

# NoIP.com

Create an easy to remember hostname and never lose your connection again.

- https://www.noip.com/