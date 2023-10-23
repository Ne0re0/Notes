# PHP Filter Bypass

## preg_replace('search','replacewith','stringtovalidate')
```php
$variable = preg_replace('foxchallenge','','foxchallfoxchallengeenge')
```
Note that the string in the middle is checked and deleted but as it is wrapped with another foxchallenge, the second isnt checked