# Ngrok (Port forwarding tool)

## USE NGROK
***FORWARD AN HTTP SERVER***
```bash
ngrok http <port where the server is running>
```
***FORWARD A TCP PORT (REVERSE SHELL)***
```bash
nc -lvp <listening port>
```
Dans un second terminal
```bash
ngrok tcp <same port>
```
The IP and port are  now the ngrok.eu.io....:<port>