
# Open()

The perl `open` function is vulnerable to `bash` code injection :

**Source code :**
```perl
$file = $1;
if(!open(F, $file)) {
    die "[-] Can't open $file: $!\n";
}
```

Payload :
```perl
| whoami |
```

