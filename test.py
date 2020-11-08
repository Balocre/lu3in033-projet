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
        self.trame_offset = 0
        self.trame_length = 0
        self.ligne = []
        self.ligne_offset = 0
        self.ligne_len = 0
        self.f = open(fichier,"r")

    def lire_ligne(self):
        """
            Lit une ligne en vérifiant l'offset et enlève les valeurs qui ne respectent pas le format demandé
            retourne une ligne de string correspondant aux octets en hexa
        """
        while True:
            self.ligne = self.f.read()
            self.ligne = self.ligne.split()
            if self.ligne == []:
                return False
            #On commence par vérifier l'offset
            if all(c in string.hexdigits for c in self.ligne[0]) == False or int(self.ligne[0], 16) != self.trame_offset:
                print ("Problème d'offset")
                continue
            #On laisse uniquement les trames dans la ligne
            for mot in self.ligne:
                if all(c in string.hexdigits for c in mot) == False or len(mot) != 2:
                    self.ligne.remove(mot)
            #On met à jour notre self.length et ligne_offset /!\ TRES PROBABLEMENT INUTILE, A REVISER PLUS TARD
            self.ligne_len = len(self.ligne)
            if self.trame_length < self.ligne_len:
                self.trame_length += self.ligne_len
            self.ligne_offset = 0
            # /!\/!\/!\ SPAGHETTI BOLOGNAISE /!\/!\/!\
            return True
            # /!\/!\/!\ SPAGHETTI BOLOGNAISE /!\/!\/!\
    
    def lire_octets(self,n):
        """
            lit n octets et retourne la string correspondante
        """
        lus = 0
        res = ""
        while lus < n:
            if self.ligne_offset == self.ligne_len :
                if not self.lire_ligne():
                    # /!\/!\/!\ SPAGHETTI BOLOGNAISE /!\/!\/!\
                    return False
                    # /!\/!\/!\ SPAGHETTI BOLOGNAISE /!\/!\/!\
            res += self.ligne[self.ligne_offset]
            self.ligne_offset += 1
            lus+=1
        return res

    def ethernet(self):
        dic = dict()
        dic["mac_dest"] = self.lire_octets(6)
        dic["mac_src"] = self.lire_octets(6)
        dic["eth_type"] = self.lire_octets(2)
        return dic

    def ip(self):
        dic = dict()
        dic["type"] = self.lire_octets(1)
        # /!\/!\/!\ SPAGHETTI BOLOGNAISE /!\/!\/!\
        dic["HL"] = self.lire_octets(1)
        # /!\/!\/!\ SPAGHETTI BOLOGNAISE /!\/!\/!\
        dic["TOS"] = self.lire_octets(2)


        # /!\/!\/!\ SPAGHETTI BOLOGNAISE /!\/!\/!\
        dic["Total_length"] = self.lire_octets(4)
        # /!\/!\/!\ SPAGHETTI BOLOGNAISE /!\/!\/!\ TODO : INCREMENTER LES ATTRIBUTS

        dic["Identifier"] = self.lire_octets(4)
        

        #/!\/!\/!\ A FINIR /!\/!\/!\
        return dic

    def tcp(self):
        pass

    def http(self):
        pass    

    def lire_trame(self):
        pass

    def lire_fichier(self):
        #Plusieurs trames
        pass

t = Trame("trame1.txt")
print(t.ethernet())

#J'ai juré ça a marché du premier coup j'ai même pas eu besoin de débugger cette merde