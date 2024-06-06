
# Chiffrement par bloc symétrique

- Découper le message en bloc de même taille que la clé

**AES :**

- on suit un mode opératoire
	- 128b - 10 tours
	- 192b - 12 tours
	- 256b - 14 tours

Basé sur des maths du cycle Université 3


| Avantages                    | Inconvénients                                |
| ---------------------------- | -------------------------------------------- |
| Très peu gourmand en mémoire | Attention à l'implémentation niveau sécurité |
| Très peu gourmand en calculs |                                              |

## Fonctionnement

1. On coupe le message en blocs de tailles 128
2. On divise chaque bloc en 16 octets
3. On les place sur une matrice carrée (4x4)
4. On réalise 10, 12 ou 14 tours suivants :
	1. Xor avec des sous clés
	2. Substitution (non linéaire sur chaque octet)
	3. Décalage des lignes + mélange des colonnes
5. On mélange les blocs grace à un **mode opératoire** (ECB, CBC, ...)

### ECB

- On peut reconnaître des patterns en cas de répétition.
### CBC (cipher bloc chaining)

![[Pasted image 20240409141714.png]]

# Chiffrement RSA

- p et q premiers, grands, très grands
- e = 65537
- d = e^-1 \[(p-1) x() q-1)]

On chiffre avec la clé publique
On déchiffre avec la clé privée

