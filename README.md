# LU3IN033 - Projet | Antoine Audras - Ali Benabdallah
*Projet semestriel de l'UE LU3IN033 (Réseaux) de Sorbonne Universités - 
implémentation d'un "Analyseur de protocole réseaux"*



## **Structure**

Le projet est composé d'un seul fichier : cybershark2077.py

Ce fichier est découpé en 3 parties majeures:
    - Parser
    - Analyser
    - UI

#### **Parser** :

Dans cette partie vous trouverez :<br>
    - Les classes et les fonctions permettant le parsing d'un fichier trace.<br>
    - Les classes composant l'AST<br>
    - La classe TraceFileParser033, qui contient les fonctions lexer et parser<br>

#### **Analyser** :
Dans cette partie se trouvent les classes associées a l'analyse des trames<br>
    - Les classes composant un objet Trace033<br>
    - La classse TraceAnalyzer033, qui regroupe les fonctions permettant d'extraire des données de l'AST et de produire un arbre représentant la trace<br>
    - Quelques fonctions permettant la manipulation des données produites

#### **UI** :
Cette partie n'est composée que de la fonction run_cursed_ui qui permet
de produire l'interface utilisateur

Le code à été pensé pour être le plus "plat" possible, avec peu d'imbrications
car c'est c'est une bonne pratique en python et celà permet de maintenir le code
plus facilement, ainsi beaucoup de variables et objets servant à la 
configuration du programme sont déclarée dans la scope globale. Elles sont 
généralement placées au dessus des fonctions qu'elles concernent.

#### **Filtres**

Voici les valeurs des champs qu'il est possible de filtrer pour chaque protocole
un filtre s'écrit de la manière suivante :<br>
```protocole1.champ1 == valeur1, protocole2.champ2 == valeur2, ...```<br>
La valeur doit être écrite en base décimale<br>

A noter que le filtrage séléctionne les trames positivement en fonction des 
filtres (ou) si vous voulez filtrez en fonction plusieurs champs (et) il faudra
faire un second filtrage sur la sortie

| protocole | champ |
|-----------|-------|
|ethernet   |dst    |
|           |src    | 
|           |type   |
|ipv4       |version|
|           |ihl    |
|           |tos    |
|           |tlength|
|           |id     |
|           |flags  |
|           |df     |
|           |mf     |
|           |frag_offset|
|           |ttl    |
|           |proto  |
|           |checksum|
|           |src    |
|           |dst    |
|tcp        |src_port|
|           |dst_port|
|           |seq    |
|           |acknum |
|           |hl     |
|           |flags  |
|           |ecn    |
|           |cwr    |
|           |ece    |
|           |urg    |
|           |ack    |
|           |psh    |
|           |rst    |
|           |syn    |
|           |fin    |
|           |win    |
|           |chksum |
|           |urgp   |
