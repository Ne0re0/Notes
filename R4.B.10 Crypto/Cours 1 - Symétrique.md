
| Flot                                       | Bloc                       |
| ------------------------------------------ | -------------------------- |
| Génère une keystream via la clé            | Décomposition en morceaux  |
| Chiffre le message avec la keystream (XOR) | chaque morceau est chiffré |
| (keystream = masque jetable)               | AES CBC, ECB, CTR          |
| Plus faible                                |                            |
|                                            |                            |
**Probleme :** Si les mêmes IV sont utilisés, le même keystream est généré. Donc, full insecure.

```
M1 xor K = C1
M2 xor K = C2

C1 xor C2 = M1 xor M2
```



