import string
dict_type = {"0800" : "IPv4 : 0x0800", "0806" : "ARP : 0x0806"}
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
    