######################################################################
#                              Atila                                 #      
######################################################################        


######################################################################
#                           librerias                                #
######################################################################

import os

# El usuario necesita ejecutar el programa como root
if os.geteuid() != 0:
    exit("Necesitas ejecutar el programa como root")

import pyfiglet
import logging
import Escaner
import Ataques

######################################################################


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
        os.system("clear")



    def show(self):                 # Funcion para mostrar el banner y el menu 
        print(self.banner)          
        print(self.menu)

    def run(self):                      # Funcion para ejecutar el menu
        self.clear()
        # Añadimos funcion para ctrl+c y ctrl+z
        try:
            while True:
                
                self.show()                     
                choice = self.get_input()
                if choice == "1":
                    self.clear()
                    # Hacemos un menu dentro de este para escanear la red
                    EscanerRed().run()

                elif choice == "2":
                    self.clear()
                    # Hacemos un menu dentro de este para realizar ataques
                    AtaquesRed().run()

                elif choice == "99":
                    exit()
                else:
                    print("Opcion invalida")
        except KeyboardInterrupt:
            print("\nSaliendo...")
            exit()

class EscanerRed:
    def __init__(self):
        self.active_computers = []
        self.menu = """
        MENÚ DE ESCANEO DE RED
        1. Escaneo de red completa
        2. Escaneo pasando ip (con o sin mascara)
        3. Escaneo de puertos para las ip encontradas
        4. Escaneo de puertos para una ip (con o sin mascara)
        99. Atras
        """
    # Funcion para obtener una de las opciones del menu
    def get_input(self):
        return input("Elige una opcion: ")

    

    # Funcion para mostrar el menu de escaneo de red
    def show(self):
        print(self.menu)


    # Funcion para ejecutar el menu de escaneo de red
    def run(self):
        scan1 = Escaner.Escaner()
        try:
            while True:
                self.show()
                choice = self.get_input()

                if choice == "1":
                    scan1.scan_ip_range()
                    if scan1.client_list != []:
                        choice = input("¿Quiere guardar los resultados? (s/n): ") # Preguntamos si quiere guardar los resultados
                        if choice == "s":
                            self.active_computers = scan1.client_list

                elif choice == "2":
                    
                    ip = input("Ejemplo de entrada -> 192.168.1.1 o 192.168.1.1/24 \nIntroduce una ip o un rango de ip: ")
                    scan1.check_ip(ip)
                    if scan1.check_ip(ip):
                        scan1.scan_ip(ip)
                        if scan1.client_list != []:
                            choice = input("¿Quiere guardar los resultados? (s/n): ") # Preguntamos si quiere guardar los resultados
                            if choice == "s":
                                self.active_computers = scan1.client_list
                    else:
                        print("Ip invalida")
                    
                elif choice == "3":
                    if self.active_computers == []:
                        print("\nNo hay ninguna ip activa o no se ha realizado ningun escaneo")
                    else:
                        scan1.scan_ports_active_ips(self.active_computers)

                elif choice == "4":
                    ip = input("Introduce la ip: ")
                    if scan1.check_ip(ip):
                        # Comprobamos si la ip tiene mascara
                        if "/" in ip:
                            self.active_computers = []
                            scan1.scan_ip(ip)
                            self.active_computers = scan1.client_list
                            for ip in self.active_computers:
                                scan1.scan_ports_active_ips(self.active_computers)        
                        else:
                            scan1.scan_ports_thread(ip)

                elif choice == "99":
                    os.system("clear")
                    break
                else:
                    print("Opcion invalida")
        except KeyboardInterrupt:
            print("\nSaliendo...")
            exit()

class AtaquesRed:
    def __init__(self):
        self.menu = """
        MENU DE ATAQUES
        1. Ataque de denegacion de servicio
        2. Ataque de falsificacion de ip MitM (ICMP Redirect)
        3. Ataque de falsificacion de ip MitM (ARP Spoofing)
        4. Ataque de falsificacion de dns MitM (DNS Spoofing)
        5. Entrada mediante exploit (vsftpd)
        99. Atras 
        """
    
    def get_input(self):
        return input("Elige una opcion: ")
    
    def show(self):
        print(self.menu)

    def run(self):
        attack1 = Ataques.Ataques()
        try:
            while True:              
                self.show()
                choice = self.get_input()

                if choice == "1":
                    print("Ataque de denegacion de servicio NO IMPLEMENTADO")
                elif choice == "2":
                    ip = input("Introduce la ip de la victima: ")
                    attack1.IcmpRedirect(ip)
                elif choice == "3":
                    ip = input("Introduce la ip de la victima: ")
                    attack1.ArpSpoofing(ip)
                elif choice == "4":
                    print("Ataque de falsificacion de dns NO IMPLEMENTADO")
                elif choice == "5":
                    ip = input("Introduce la ip de la victima: ")
                    str(ip)
                    attack1.exploit_vsftpd(ip)
                elif choice == "99":
                    os.system("clear")
                    break
                else:
                    print("Opcion invalida")
        except KeyboardInterrupt:
            print("\nSaliendo...")
            exit()

# Quitamos los logs de scapy para que no se muestren por pantalla al ejecutar el programa
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

menu1 = menu()
menu1.run()
