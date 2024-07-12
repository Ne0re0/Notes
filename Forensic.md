# Forensic

## Disk analysis

### Looking for files

tools:
- foremost
- binwalk
- scalpel
- testdisk
- icat
- fls

### doc : 
https://heisenberk.github.io/Not-So-FAT-FCSC-2019/


## Dump analysis
- volatility  
https://repository.root-me.org/Forensic/EN%20-%20Volatility%20cheatsheet%20v2.4.pdf?_gl=1*s7dztd*_ga*MTIzODI2NDMyMi4xNjc0NTUzMTQx*_ga_SRYSKX09J7*MTY4NTYxOTk0MS41Ni4xLjE2ODU2MjE5MDQuMC4wLjA

```bash
volatility -f FILE what_to_do
volatility -f File imageinfo # display infos
volatility -f File --profile=Win7SP0x86 envars # display env variable for the given profile
```

## Network analysis
- wireshark
- Volatility