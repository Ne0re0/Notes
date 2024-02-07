# Custom wordlist generation

- cewl
- pipal
- john
- CUPP
- Crunch

### Website based

- `cewl` parse the source code and retrieve words that can be used in passwords
```bash
cewl http://target.com -w outfile.txt
```
- Retrieve the top ten passwords
```bash
pipal outfile.txt | grep -A "Top 10 passwords" | tail -n +2 | awk -F '=' '{print $1}' | tr 'A-Z' 'a-z' > top_10_passwords.txt
```

## CUPP
```bash
cupp -i # Enter interactive mode
```
## John rules

| Rule name | rule name |
| ---- | ---- |
| add1234_everywhere | **l33t** |
| add2010everywhere | **login-generator** |
| adddotcom | **login-generator-i** |
| addjustnumbers | loopback |
| all | monthsfullpreface |
| append1_addspecialeverywhere                    |multiword  |
| append2letters | none |
| append2numspecial | nt |
| append3numspecial | o |
| append4num | o1 |
| append4numspecial | o2 |
| append5num | o3 |
| append6num | oi |
| appendcap-num_or_special-twice         |         oldoffice  |
| appendcurrentyearspecial                    |    passphrase-rule1   |
| appendjustnumbers | passphrase-rule2 |
| appendjustspecials | phrase |
| appendjustspecials3times                         | phrasecaseone |
| appendmonthcurrentyear                           | phrasepreprocess |
| appendmonthday | phrasewrap |
| appendseason | prependcapcapappendspecial |
| appendspecial3num | prependdaysweek |
| appendspecial4num | prependhello |
| appendspecialatend2                           | prependnumnum |
| appendspecialatend5                      | prependnumnumnum |
| appendspecialatend8                              | prependseason |
| appendyears | prependspecialspecialappendnumbersnumbernumber |
| appendyears_addspecialeverywhere                 | prependyears |
| best64 | replaceletters |
| d3ad0ne | replaceletterscaps |
| devprodtestuat | replacenumbers |
| dive | replacenumbers2special |
| drop | replacespecial2special |
| extra | rockyou-30000 |
| hashcat | shifttoggle |
| help | single |
| i | single-extra |
| i1 | specific |
| i2 | split |
| i3 | t0xlc |
| insidepro | t9 |
| jumbo | unicodesubstitution |
| jumbosingle | upperunicodesubstitution |
| korelogic | wordlist |


```bash
john --wordlist=informations.txt --rules=RULE_NAME --stdout
```
## Username generation

| Rule name |
| ---- |
| Login-Generator |
| Login-Generator-i |
## Password variations

| Rule name | What it does |
| ---- | ---- |
| l33t | Edit case, convert some letters to variations (e.g. `i` to `!` or `1`) |

