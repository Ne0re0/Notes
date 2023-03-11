BurpSuite

Intruder :

	Attack types :


		Sniper : on admet une liste de mot {burp, suite}

			requête de base : username=§pentester§&password=§Expl01ted§ 

			username=burp&password=Expl01ted
			username=suite&password=Expl01ted
			username=pentester&password=burp
			username=pentester&password=suite



		Battering RAM : on admet une liste de mot {burp, suite}

			requête de base : username=§pentester§&password=§Expl01ted§ 

			username=burp&password=burp
			username=suite&password=suite


		Pitchfork: Comme sniper mais avec plusieurs payloads en simultanés
			on admet une liste de username {mike, joe} et de passwd {skill, 1234}

			requête de base : username=§pentester§&password=§Expl01ted§ 

			username=mike&password=skill
			username=joe&password=1234
			
		ClusterBomb : 
			on admet une liste de username {mike, joe} et de passwd {skill, 1234}
			
			requête de base : username=§pentester§&password=§Expl01ted§ 
			
			username=mike&password=skill
			username=joe&password=skill
			username=mike&password=1234
			username=joe&password=1234
			
DECODER :
	ENCODE 
	DECODE
	HASH
	(hashes are created in ASCII HEX so we have to encode in ASCII TEXT to solve)
	(Il faut bien prendre le retour chariot à la fin de ce qu'on veut hash s'il existe)

SEQUENCER :
	SEND THOUSANDS OF REQUEST TO ANALYSE COOKIE PREDICTION
		
