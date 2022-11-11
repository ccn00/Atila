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

    # Escanea una ip o un rango de ips dadas por el usuario
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
        else:
            # Mostramos los clientes encontrados en forma de tabla
            print("IP\t\t\tMAC Address")
            for client in self.client_list:
                print(client["ip"] + "\t\t" + client["mac"])

        return self.client_list

    # Escanea el rango de ips de la red
    def scan_ip_range(self):
        # Mandamos un scan de ips con el rango de ips en base a la tarjeta de red
        scan_result = self.scan_ip(self.get_ip_range())
        self.print_result_ip(self, scan_result)


    # Para mejorar el rendimiento del escaneo de puertos lo realizamos en paralelo con hilos
    def scan_ports_thread(self, ip):
        print("\nEscaneando puertos de la ip: " + ip)
        print ("PORT\t\tSTATE\t\tSERVICE")
        # Creamos un hilo para cada puerto
        for puerto in range(1, 1025):
            t = threading.Thread(target=self.scan_ports, args=(ip, puerto))
            t.start()


    # Escaner de puertos para una ip
    def scan_ports(self, ip, puerto):
        # print("Escaneando puertos de la ip: " + ip)
        # print ("PORT\t\tSTATE\t\tSERVICE")

        # RandShort() genera un puerto aleatorio para el scan por tanto el escaneo se realizara cada vez con un puerto diferente
        origin_port = scapy.RandShort()
        # Creamos un paquete TCP con la ip introducida por el usuario y el puerto que queremos escanear
        packet = scapy.sr1(scapy.IP(dst=ip)/scapy.TCP(sport=origin_port, dport=puerto, flags="S"), timeout=0.0005, verbose=False)   
        if packet is not None:
            # perfcounter_start = time.perf_counter()
            if packet.haslayer(scapy.TCP):
                if packet.getlayer(scapy.TCP).flags == 0x12:
                    print(str(puerto) + "\t\tOpen\t\t" + socket.getservbyport(puerto))
                    # Enviamos un paquete RST para cerrar la conexion
                    scapy.sr1(scapy.IP(dst=ip)/scapy.TCP(sport=origin_port, dport=puerto, flags="R"), timeout=0.05, verbose=False)
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
        list_of_ips = []
        for ip in client_list:
            self.scan_ports_thread(ip["ip"])
        #     list_of_ips.append(ip["ip"])
        # for ip in list_of_ips:
        #     self.scan
        

        


    #############################################################################################################
    #                                             ZONA PRINTS                                                   #
    #############################################################################################################

    def print_result_ip(scan_result):
        print("IP\t\t\tMAC Address")
        # Recorremos la lista de clientes encontrados
        for client in scan_result:
            print(client["ip"] + "\t\t" + client["mac"])