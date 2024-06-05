#!/bin/python

from hashlib import md5

d = 23
e = 7
n = 55

def getSignature(message,d,n):
    hash = md5(message).hexdigest()  # Utilisation de hexdigest() pour obtenir une chaîne hexadécimale
    signature = (int(hash, 16)**d) % n  # Convertir la chaîne hexadécimale en entier
    return signature

def validateIntegrity(message,signature,e,n) : 
    hash = int(md5(message).hexdigest(),16) % n
    verify = (signature**e) % n
    return verify == hash


message = b"IUT{C4_C357_DU_F14G}"
signature = getSignature(message,d,n)

print(f"message : {message}")
print(f"signature : {signature}")
print(f"Integrity : {validateIntegrity(message,signature, e,n)}")


