import string
import numpy as np 
dict_type = {"0800" : "IPv4 : 0x0800", "0806" : "ARP : 0x0806"}
"""
    f = open ("trame1.txt","r")
    L = []
    for ligne in f:
        L.append(ligne.split())
    for ligne in L:
        for mot in ligne:
            if all(c in string.hexdigits for c in mot) == False or len(mot) != 2:
                ligne.remove(mot)
    L.remove([])
    #Ethernet
    print("Champ Ethernet MAC destination : "+ str(L[0][0:6])) #Concatenable deuspi
    print("Champ Ethernet MAC source : "+ str(L[0][6:12]))  #Pareil
    type = L[0][12]+L[0][13]
    print("Champ Ethernet Type : "+ dict_type[type])

    #IP
    if type=="0800":
        print("Champ IP Version : "+str(L[0][14][0]))
        hl = int(L[0][14][1]) * 4
        print("Champ IP, Header Length : "+str(hl))
        print("Champ IP Version : "+str(L[0][15]))
        tl = int(L[0][16]+L[0][17], 16)  
        print("Champ IP, Total Length : "+str(tl)) #total de la trame c'est tl + 14 (d'internet)
    #ETC...
"""
class Trame:
    
    def __init__(self,fichier):
        trame_offset = 0
        trame_length = 0
        ligne = []
        ligne_offset = 0
        ligne_len = 0
        f = open(fichier,"r")

    def lire_ligne(self):
        """
            Lit une ligne en vérifiant l'offset et enlève les valeurs qui ne respectent pas le format demandé
            retourne une ligne de string correspondant aux octets en hexa
        """
        while True:
            self.ligne = self.f.read()
            self.ligne = self.ligne.split()
            if self.ligne == []:
                raise Exception("EOF")
            #On commence par vérifier l'offset
            if all(c in string.hexdigits for c in L[0]) == False or int(self.ligne[0], 16) != self.trame_offset:
                print ("Problème d'offset")
                continue
            #On laisse uniquement les trames dans la ligne
            for mot in self.ligne:
                if all(c in string.hexdigits for c in mot) == False or len(mot) != 2:
                    self.ligne.remove(mot)
            #On met à jour notre self.length et ligne_offset /!\ TRES PROBABLEMENT INUTILE
            self.ligne_len = len(ligne)
            if self.trame_length < self.ligne_len:
                self.trame_length += self.ligne_len
            self.ligne_offset = 0

            return ligne
    
    def lire_octets(self,n):
        lus = 0
        res = ""
        while lus < n:
            if self.ligne_offset == self.ligne_len :
                self.ligne = lire_ligne()
            res += ligne[self.ligne_offset]
            self.ligne_offset += 1
            lus+=1
        return res
        
    def lire_trame(self):
        pass

    def lire_fichier(self):
        #Plusieurs trames
        pass