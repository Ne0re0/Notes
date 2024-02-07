# BloodHound / SharpHound

## Enumeration w/ BloodHound

Bloodhound is a graphical interface that allows you to visually map out the network. This tool along with SharpHound which similar to PowerView takes the user, groups, trusts etc. of the network and collects them into .json files to be used inside of Bloodhound.

### 1. Active directy harvesting w/ SharpHound
```cmd
powershell -ep bypass
```

Load SharpHound
```powershell
. .\Downloads\SharpHound.ps1 
```

Let's gather infos 
```powershell  
Invoke-Bloodhound -CollectionMethod All -Domain DOMAIN_NAME -ZipFileName loot.zip
```

Let's download `loot.zip` to our machine  
 
Example w/ ssh (scp) :
```bash
scp Administrator@CONTROLLER:C:/Users/Administrator/20230424130956_loot.zip .
```

### 2. Mapping the network w/ BloodHound
- launch `neo4j` database and `bloodhound` in our machine
```bash
sudo neo4j console &
bloodhound
```

This will ask you to change your bloodhound password  
Default - neo4j:neo4j
- Drag and drop loot.zip inside bloodhound
- Click on the top left three lines button 
- Click on analysis and look at how strong bloodhound is
