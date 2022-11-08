import logging

# Quitamos los logs de scapy para que no se muestren por pantalla al ejecutar el programa
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

import scapy.all as scapy
import socket


# El usuario introduce la ip de la red que quiere escanear o el rango de ips
ip = input("Introduce la ip: ")

############################################################################################################
#                                        METODOS PARA ESCANEO                                                #
############################################################################################################

def check_ip(ip):
    # Comprobamos que la ip introducida es valida
    if "." in ip:
        octetos = ip.split(".")
        if len(octetos) == 4:
            for octeto in octetos:
                if octeto.isdigit():
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


def scan_ip(ip):
    print ("Escaneando ip: " + ip)
    arp_request = scapy.ARP(pdst=ip)                    # Creamos un paquete ARP con la ip introducida por el usuario
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")    # Creamos un paquete ethernet con la direccion de broadcast
    arp_request_broadcast = broadcast/arp_request       # Unimos los dos paquetes

    # Enviamos el paquete y recibimos la respuesta
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]   
    clients_list = []                                  # Creamos una lista para guardar los clientes encontrados
    for element in answered_list:                      # Recorremos la lista de clientes encontrados
        # Creamos un diccionario con la ip y la mac de cada cliente
        client_dict = {"ip": element[1].psrc, "mac": element[1].hwsrc}  
        clients_list.append(client_dict)
    return clients_list


# Escaner de puertos para una ip
def scan_ports(ip):
    print("Escaneando puertos de la ip: " + ip)
    print ("PORT\t\tSTATE\t\tSERVICE")
    for puerto in range(1, 1024):
        # RandShort() genera un puerto aleatorio para el scan por tanto el escaneo se realizara cada vez con un puerto diferente
        origin_port = scapy.RandShort()
        packet = scapy.sr1(scapy.IP(dst=ip)/scapy.TCP(sport=origin_port, dport=puerto, flags="S"), timeout=1, verbose=False)   
        if packet is not None:
            if packet.haslayer(scapy.TCP):
                if packet.getlayer(scapy.TCP).flags == 0x12:
                    print(str(puerto) + "\t\tOpen\t\t" + socket.getservbyport(puerto))
                    # Enviamos un paquete RST para cerrar la conexion
                    scapy.sr1(scapy.IP(dst=ip)/scapy.TCP(sport=origin_port, dport=puerto, flags="R"), timeout=1, verbose=False)
                # elif packet.getlayer(scapy.TCP).flags == 0x14:
                #     print(str(puerto) + "\t\tClosed\t\t" + socket.getservbyport(puerto))
            elif packet.haslayer(scapy.ICMP):
                if int(packet.getlayer(scapy.ICMP).type) == 3 and int(packet.getlayer(scapy.ICMP).code) in [1,2,3,9,10,13]:
                    print(str(puerto) + "\t\tFiltered\t" + socket.getservbyport(puerto))


# Escaner de puertos para ips activas en la red
def scan_ports_active_ips():
    active_clients = scan_ip(ip)
    print("Escaneando puertos de las ips activas")
    for client in active_clients:
        scan_ports(client["ip"])


    

    

#############################################################################################################
#                                             ZONA PRINTS                                                   #
#############################################################################################################

def print_result_ip(scan_result):
    print("IP\t\t\tMAC Address")
    # Recorremos la lista de clientes encontrados
    for client in scan_result:
        print(client["ip"] + "\t\t" + client["mac"])



if check_ip(ip):
    scan_ports(ip)
    # scan_result = scan_ip(ip)
    # print_result_ip(scan_result)
else:
    print("IP invalida por favor introduce una ip valida")

