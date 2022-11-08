######################################################################
#                              Atila                                 #      
######################################################################        

import pyfiglet
import os


class menu:
    def __init__(self):
        self.banner = pyfiglet.figlet_format("Atila" , font = "slant" )
        self.menu = """
        1. Escaneo de red
        2. Ataques
        99. Exit
        """



    def get_input(self):
        return input("Elige una opcion: ")

    def clear(self):
        os.system("cls")

    def show(self):                 # Funcion para mostrar el banner y el menu 
        print(self.banner)          
        print(self.menu)

    def run(self):                      # Funcion para ejecutar el menu
        while True:
            self.show()                     
            choice = self.get_input()
            if choice == "1":
                # Hacemos un menu dentro de este para escanear la red
                
                pass        

            elif choice == "2":
                pass
            elif choice == "99":
                exit()
            else:
                print("Opcion invalida")
            self.clear()

class EscanerRed:
    def __init__(self):
        self.menu = """
        1. Escaneo de red completa
        2. Escaneo por ip
        3. Escaneo de puertos para las ip encontradas
        4. Escaneo de puertos para una ip
        99. Atras
        """




class Ataques:
    def __init__(self):
        self.menu = """
        1. Ataque de denegacion de servicio
        2. Ataque de falsificacion de ip MitM (ICMP Redirect)
        3. Ataque de falsificacion de ip MitM (ARP Spoofing)
        4. Ata
        """
        pass



menu1 = menu()
menu1.run()
