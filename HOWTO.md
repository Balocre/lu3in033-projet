### Installation:
    Pour utiliser ce programme il vous faudra installer python 3.9 sur votre machine.
    Si vous utilisez un systême UNIX le code devrait marcher nativement.
    Si vous utilisez Windows vous devrez installer le module.
    ```windows-curses``` avec la commande 
    ```python -m pip install windows-curses```

### Utilisation:
    Le code s'execute avec la commande :
    ```python cybershark2077.py```

    Le programme va procéder à l'analyse du fichier trace passé en 
    entrée puis ouvrir l'interface graphique (veillez à avoir un terminal
    assez grand lors de l'execution du programme car l'UI ne se redimensionne
    pas).

    Vous pouvez ensuite naviguer à l'aide des flèches du clavier, bas haut pour 
    faire défiler les éléments des menus, gauche droite pour naviguer entre les 
    menus.

    Le menu de gauche contient des trames ethernet, les protocoles contenus par 
    ces trames et la taille de chaque trame en octet.
    Le menu central montre une liste des headers des protocoles reconnus.
    La fenêtre de droite elle affiche les valeures des champs contenus par les
    header.

    Vous pouvez quitter le programme en appuyant sur la touche q.

### Fonctions
    Le programme est doté de quelque fonctions de manipulation des données, 
    vous pouvez éxécuter ces fonctions en appuyant sur la touche f. Un invite de
    commande s'affichera alors au bas de l'UI.

    Le programme est doté d'une capacité de filtrage basique, pour l'utiliser il
    faut invoquer la fonction ```filter```. Les arguments à soumettre sont les 
    filtres sur le  modèle ```protocole.champ == valeur``` ou champ est un 
    attribut d'une des classes noeud d'un arbre trace.

    Il est possible de charger un nouveau fichier trace depuis le programme en
    invoquant la fonction open et en passant en argument le chemin relatif d'un
    fichier trace.

    Il y a une fonctionnalité d'import et d'export depuis/vers un fichier  binaire 
    "pickle", utilisable grâce aux fonctions import_pickle et export_pickle avec 
    le nom du fichier.

    Enfin il est possible d'exporter le résultat de l'analyse dans un format 
    lisible par les humains avec la fonction ```dump_it```