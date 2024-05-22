# Secure-String bypass

**Read a secure string value**
```powershell
echo "password" | ConvertTo-SecureString | ConvertFrom-SecureString
```

**Decrypt the password**
```powershell
$pass = "01000000d08c9ddf0115d1118c7a00c04fc297eb01000000e4a07bc7aaeade47925c42c8be5870730000000002000000000003660000c000000010000000d792a6f34a55235c22da98b0c041ce7b0000000004800000a00000001000000065d20f0b4ba5367e53498f0209a3319420000000d4769a161c2794e19fcefff3e9c763bb3a8790deebf51fc51062843b5d52e40214000000ac62dab09371dc4dbfd763fea92b9d5444748692" | convertto-securestring
$user = "HTB\Tom"
$cred = New-Object System.management.Automation.PSCredential($user, $pass)
$cred.GetNetworkCredential() | fl

UserName       : Tom
Password       : 1ts-mag1c!!!
SecurePassword : System.Security.SecureString
Domain         : HTB
```

# Shell spawner

```powershell
cmd.exe
powershell.exe
powershell-ise.exe
bash.exe
```

# Sources

https://book.hacktricks.xyz/windows-hardening/basic-powershell-for-pentesters