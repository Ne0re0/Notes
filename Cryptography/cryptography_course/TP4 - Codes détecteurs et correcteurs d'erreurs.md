
# Introduction

Dans le domaine des communications numériques, la fiabilité de la transmission des données est essentielle. Les codes correcteurs d’erreurs sont des outils fondamentaux pour détecter et corriger les erreurs qui peuvent survenir lors de la transmission de données numériques sur des canaux perturbés.

Dans ce TP, nous explorerons différentes techniques de correction d’erreurs, notamment le code de parité, le code de répétition, et le code de Hamming, et nous implémenterons des solutions pour encoder et décoder des messages en utilisant ces codes.

Vous pouvez utiliser les outils que vous souhaitez pour réaliser ce TP.

# 1 Code détecteur d’erreur
##### Question 1. Implémenter un fonction prenant en entrée un message a et renvoyant le résultat après application du code de parité.

##### Question 2. Proposer et implémenter une fonction se basant sur le code de parité et étant plus performant pour la détection d’une multitude d’erreurs.
##### Question 3. Implémenter un fonction prenant en entrée un message a et un paramètre k et renvoyant le résultat après application du code de k répétitions.
##### Question 4. Implémenter un fonction prenant en entrée un message a et renvoyant le résultat de après application du code de Hamming.

# 2 Code correcteur d’erreur
##### Question 5. Supposons que l’on reçoit un message v condition par un code à k répétition et qui a pu être altéré lors de l’envoie. Implémenter une fonction permettant de retrouver le message originel u.
##### Question 6. Supposons que l’on reçoit un message v de 7 bits conditionné par un code de Hamming et qui a pu être altéré de 1 bit lors de l’envoie. Implémenter une fonction permettant de retrouver le message originel u.

##### Question 7. Même question pour un message v de taille quelconque dans lequel au plus 1 bit est altéré tous les 7 bits.