# Java tips

## Change the current version
List available versions
```bash
java --version
update-java-alternatives --list
```

Change version
```bash
sudo update-java-alternatives --set /path/to/java/version
```

Examples :
```bash
sudo update-java-alternatives --set /usr/lib/jvm/java-1.11.0-openjdk-amd64
sudo update-java-alternatives --set /usr/lib/jvm/java-1.17.0-openjdk-amd64
```