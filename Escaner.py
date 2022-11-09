import scapy.all as scapy
import socket
import thread 

class Escaner:
    # # El usuario introduce la ip de la red que quiere escanear o el rango de ips
    # ip = input("Introduce la ip: ")

    def __init__(self):
        self.client_list = []

    ############################################################################################################
    #                                        METODOS PARA ESCANEO                                                #
    ############################################################################################################

    def check_ip(ip):
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

        for element in answered_list:                      # Recorremos la lista de clientes encontrados
            # Creamos un diccionario con la ip y la mac de cada cliente
            client_dict = {"ip": element[1].psrc, "mac": element[1].hwsrc} 
            if client_dict not in self.clients_list: 
                self.clients_list.append(client_dict)
        return self.clients_list

    # Escanea el rango de ips de la red
    def scan_ip_range(self):
        # Mandamos un scan de ips con el rango de ips en base a la tarjeta de red
        scan_result = self.scan_ip(self.get_ip_range())
        self.print_result_ip(scan_result)


    # Escaner de puertos para una ip
    def scan_ports(ip):
        print("Escaneando puertos de la ip: " + ip)
        print ("PORT\t\tSTATE\t\tSERVICE")
        for puerto in range(1, 1024):
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
                elif packet.haslayer(scapy.ICMP):
                    if int(packet.getlayer(scapy.ICMP).type) == 3 and int(packet.getlayer(scapy.ICMP).code) in [1,2,3,9,10,13]:
                        print(str(puerto) + "\t\tFiltered\t" + socket.getservbyport(puerto))
            # perfcounter_end = time.perf_counter() - perfcounter_start
            # print ("Tiempo de escaneo: " + str(perfcounter_end) + " segundos")

            

    # Obtenemos la ip de la tarjeta de red
    def get_ip_range(self):
        # Obtenemos la ip de la tarjeta de red
        ip = socket.gethostbyname(socket.gethostname())
        # Separamos la ip en octetos
        octetos = ip.split(".")
        # Creamos el rango de ips
        ip_range = octetos[0] + "." + octetos[1] + "." + octetos[2] + ".1/24"
        return ip_range

    # Escaner de puertos para ips activas en la red
    def scan_ports_active_ips(self):
        # Mandamos un scan de ips con el rango de ips en base a la tarjeta de red
        active_clients = self.scan_ip(self.get_ip_range())
        print("Escaneando puertos de las ips activas")
        for client in active_clients:
            self.scan_ports(client["ip"])


    #############################################################################################################
    #                                             ZONA PRINTS                                                   #
    #############################################################################################################

    def print_result_ip(scan_result):
        print("IP\t\t\tMAC Address")
        # Recorremos la lista de clientes encontrados
        for client in scan_result:
            print(client["ip"] + "\t\t" + client["mac"])