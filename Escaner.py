import scapy.all as scapy
import socket
import threading

class Escaner:
    # # El usuario introduce la ip de la red que quiere escanear o el rango de ips
    # ip = input("Introduce la ip: ")

    def __init__(self):
        self.client_list = []

    ############################################################################################################
    #                                        METODOS PARA ESCANEO                                                #
    ############################################################################################################

##############   SECCION DE IP ############################

    def check_ip(self, ip):
        # Comprobamos que la ip introducida es valida
        if "." in ip:
            # Separamos la ip en una lista de octetos
            octetos = ip.split(".")
            if len(octetos) == 4:
                for octeto in octetos:
                    # Comprobamos que los octetos son numeros
                    if octeto.isdigit():
                        # Comprobamos que los octetos estan entre 0 y 255
                        if int(octeto) >= 0 and int(octeto) <= 255:
                            return True
                        else:
                            return False
                    else:
                        return False
            else:
                return False
        else:
            return False
        return True

    # Comprobamos si la ip esta activa 
    def scan_unique_ip(self, ip):
        # Creamos un paquete ICMP con la ip introducida por el usuario
        icmp_request = scapy.IP(dst=ip)/scapy.ICMP()
        # Enviamos el paquete y recibimos la respuesta
        answered_list = scapy.sr1(icmp_request, timeout=1, verbose=False)
        # Obtenemos la mac de la ip con scapy
        mac = scapy.getmacbyip(str(ip))
        # Si la respuesta es None la ip no esta activa
        if answered_list == None:
            print("La ip no esta activa")
        else:
            print("La ip " + ip + " esta activa y tiene como MAC: " + mac)
        
        

    # Escanea una la red completa dada una ip
    def scan_ip(self, ip):
        print ("Escaneando ip: " + ip)
        arp_request = scapy.ARP(pdst=ip)                    # Creamos un paquete ARP con la ip introducida por el usuario
        broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")    # Creamos un paquete ethernet con la direccion de broadcast
        arp_request_broadcast = broadcast/arp_request       # Unimos los dos paquetes
        # Enviamos el paquete y recibimos la respuesta
        answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]  

        # Recorremos la lista de clientes encontrados
        for element in answered_list:
            client_dict = {"ip": element[1].psrc, "mac": element[1].hwsrc}
            # Incluir a la lista si no esta ya
            if client_dict not in self.client_list:
                self.client_list.append(client_dict)

        if len(self.client_list) == 0:
            print("No se han encontrado clientes")
        elif '/' in ip:
            # Mostramos los clientes encontrados en forma de tabla
            print("IP\t\t\tMAC Address")
            for client in self.client_list:
                print(client["ip"] + "\t\t" + client["mac"])

            

        return self.client_list

    # Escanea el rango de ips de la red
    def scan_ip_range(self):
        # Mandamos un scan de ips con el rango de ips en base a la tarjeta de red
        print("Escaneando rango de ips para la red local con la tarjeta de red por defecto")
        input("¿Desea cambiar la interfaz por defecto? (eth0) (s/n): ")
        if input == "s":
            eth = input("Introduzca la interfaz: ")
            # Comprobamos que la interfaz existe
            if scapy.get_if_hwaddr(eth) == None:
                print("La interfaz no existe")
                return  # Salimos de la funcion
        else:
            eth = "eth0"

        print("Se utilizara la mascara por defecto: /24")
        input("¿Desea cambiar la mascara por defecto? (s/n): ")
        if input == "s":
            mask = input("Introduzca la mascara de red con digitos (ejemplo: 24)\n  -> ")
            # Comprobamos que la mascara es un numero
            if mask.isdigit():
                # Comprobamos que la mascara esta entre 0 y 32
                if int(mask) >= 0 and int(mask) <= 32:
                    pass
                else:
                    print("La mascara no es valida")
                    return  # Salimos de la funcion
            
        else:
            mask = "24"
        
        host_ip = scapy.get_if_addr(eth)
        ip_src = host_ip.split(".")
        ip_src = ip_src[0] + "." + ip_src[1] + "." + ip_src[2] + ".1" + "/" + mask

        self.scan_ip(ip_src)
        
################### SECCION DE PUERTOS ############################

    # Para mejorar el rendimiento del escaneo de puertos lo realizamos en paralelo con hilos
    def scan_ports_thread(self, ip):
        print("\nEscaneando puertos de la ip: " + ip)
        print ("PORT\t\tSTATE\t\tSERVICE")
        # Creamos un hilo para cada puerto
        for puerto in range(1, 1025):
            t = threading.Thread(target=self.scan_ports, args=(ip, puerto))
            t.start()
            # # Para que no se creen demasiados hilos
            # if puerto % 100 == 0:
            #     t.join()
            


    # Escaner de puertos para una ip
    def scan_ports(self, ip, puerto):
        # print("Escaneando puertos de la ip: " + ip)
        # print ("PORT\t\tSTATE\t\tSERVICE")

        # RandShort() genera un puerto aleatorio para el scan por tanto el escaneo se realizara cada vez con un puerto diferente
        origin_port = scapy.RandShort()
        # Creamos un paquete TCP con la ip introducida por el usuario y el puerto que queremos escanear
        packet = scapy.sr1(scapy.IP(dst=ip)/scapy.TCP(sport=origin_port, dport=puerto, flags="S"), timeout=1, verbose=False)   
        if packet is not None:
            # perfcounter_start = time.perf_counter()
            if packet.haslayer(scapy.TCP):
                if packet.getlayer(scapy.TCP).flags == 0x12:
                    print(str(puerto) + "\t\tOpen\t\t" + socket.getservbyport(puerto))
                    # Enviamos un paquete RST para cerrar la conexion
                    scapy.sr1(scapy.IP(dst=ip)/scapy.TCP(sport=origin_port, dport=puerto, flags="R"), timeout=1, verbose=False)
                # elif packet.getlayer(scapy.TCP).flags == 0x14:
                #     print(str(puerto) + "\t\tClosed\t\t" + socket.getservbyport(puerto))
            # elif packet.haslayer(scapy.ICMP):
            #     if int(packet.getlayer(scapy.ICMP).type) == 3 and int(packet.getlayer(scapy.ICMP).code) in [1,2,3,9,10,13]:
            #         print(str(puerto) + "\t\tFiltered\t" + socket.getservbyport(puerto))
        # perfcounter_end = time.perf_counter() - perfcounter_start
        # print ("Tiempo de escaneo: " + str(perfcounter_end) + " segundos")

            

    # Obtenemos la ip de la tarjeta de red
    def get_ip_range(self):
        # Obtenemos la ip de la tarjeta de red ethernet 0 (eth0)
        ip = socket.gethostbyname(socket.gethostname())
        # Separamos la ip en octetos
        octetos = ip.split(".")
        # Creamos el rango de ips
        ip_range = octetos[0] + "." + octetos[1] + "." + octetos[2] + ".1/24"
        return ip_range

    # Escaner de puertos de las ips activas encontradas en la red
    # Pasamos una lista de diccionarios con las ips y macs de los clientes encontrados
    def scan_ports_active_ips(self, client_list):
        for ip in client_list:
            self.scan_ports_thread(ip["ip"])
        #     list_of_ips.append(ip["ip"])
        # for ip in list_of_ips:
        #     self.scan
