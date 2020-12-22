# LU3IN033 - Projet | Antoine Audras - Ali Benabdallah
*Projet semestriel de l'UE LU3IN033 (Réseaux) de Sorbonne Universités - 
implémentation d'un "Analyseur de protocole réseaux"*



### Structure

Le projet est composé d'un seul fichier : projet.py

Ce fichier est découpé en 3 parties majeures:
    - Parser
    - Analyser
    - UI

#### Parser :

Dans cette partie vous trouverez les classes et les fonctions permettant le
parsing d'un fichier trace.
    - Les classes composant l'AST
    - La classe TraceFileParser033, qui contient les fonctions lexer et parser

#### Analyser :
Dans cette partie se trouvent les classes associées a l'analyse des trames
    - Les classes composant un Trace033
    - La classse TraceAnalyzer033, qui regroupe les fonctions permettant 
        d'extraire des données de l'AST et de produire un arbre représentant la
        trace
    - Quelques fonctions permettant la manipulation des données produites

#### UI :
Cette partie n'est composée que de la fonction run_cursed_ui qui permet
de produire l'interface utilisateur

Le code à été pensé pour être le plus "plat" possible, avec peu d'imbrications
car c'est c'est une bonne pratique en python et celà permet de maintenir le code
plus facilement, ainsi beaucoup de variables et objets servant à la 
configuration du programme sont déclarée dans la scope globale. Elles sont 
généralement placées au dessus des fonctions qu'elles concernent.
