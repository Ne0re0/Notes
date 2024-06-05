
# Conditions

```bash
if test $VAR -eq 123 ; then 
if [[ $VAR -eq 123 ]] ; then 
if [ $VAR -eq 123 ] ; then 
if (( $VAR -eq 123 )); then 
```

- ***0 means true***
- ***1 means false***
- ***An empty string is 1***
- ***A non emptu string is 0***

### Comparisons

| comparator                  | Utlity                                   |
| --------------------------- | ---------------------------------------- |
| -eq / -lt / -gt / -le / -ge | They are all used against integer values |
| = / == / !=                 | They are used to compare strings         |


## Unquoted expression injection

When a variable appear unquoted in a script, command flags can be maliciously added because strings are split into an array of words (split on spaces)

**Example :**
```bash
if test $PASS -eq ${1} ; then 
	echo "success"
else
	echo "Nop"
fi
```

```bash
./script "1 -o randomstring"
```

In this case, by passing `"1 -o randomstring"` to the script, it will print `success`

Explanation : 
- To the `test` command, the `-o` equals to `||` 
- So it is testing if `$PASS` equals to 1 which is probably false
- **OR** if `randomstring` is true (a non empty string is always true in bash)
- So it prints `success`

## Bash -v injection `[[! -v "$1"]]`

If \$1 is something like `x[$(touch /tmp/pwned)]` then the command is executed

**Note :** The $1 value must be single quoted, either, it will be interpreted before actually accessing the script

**POC**
```bash
./vuln_binary 'x[$(touch /tmp/pwned)]'
```

