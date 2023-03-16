# BurpSuite

This common tool needs the firefox extension FoxyProxy to run with
## Proxy 
With this section, you can see request before the sending.  
This is pretty useful when you need only one try.
Si il y a besoin de plus, on peut envoyer la requête au repeater (CTRL+R)

## Repeater 
This works as the proxy section but you can send edit de the same request as much as you want.
In this section, you'll need to edit requests by hand.  
If you want to bruteforce, send to request to the Intruder. (CTRL+I)

## Intruder :
This is the third most useful section within BurpSuite.  
This one allows us to give a wordlist and bruteforce given variables

In the payload subsection, we can choose various attack types : 
### Attack types :


#### Sniper : on admet une liste de mot {burp, suite}

***requête de base :***   
```username=§pentester§&password=§Expl01ted§ ```

1. username=burp&password=Expl01ted
2. username=suite&password=Expl01ted
3. username=pentester&password=burp
4. username=pentester&password=suite



#### Battering RAM : on admet une liste de mot {burp, suite}

***requête de base :***  
``` username=§pentester§&password=§Expl01ted§``` 

0. username=pentester&password=Expl01ted
1. username=burp&password=burp
2. username=suite&password=suite


#### Pitchfork: Comme sniper mais avec plusieurs payloads en simultanés
on admet une liste de username{mike, joe} et de passwd {skill, 1234}

***requête de base :***  
``` username=§pentester§&password=§Expl01ted§ ```

1. username=mike&password=skill
2. username=joe&password=1234

#### ClusterBomb : 
on admet une liste de username {mike, joe} et de passwd {skill, 1234}

***requête de base : ***  
```username=§pentester§&password=§Expl01ted§``` 

1. username=mike&password=skill
2. username=joe&password=skill
3. username=mike&password=1234
4. username=joe&password=1234

## SEQUENCER :
This section can be used to send thousand prediction to analyse cookie prediction



## Following are much less useful than previous ones
## DECODER :
***CyberChef is much more powerful***

## Extension
This section can be used to add some powerful user codded features.  
***Logger ++*** is used to log everything that you'll try.  It can save some jail times in somes cases :thumbsup: