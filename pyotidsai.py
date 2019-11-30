import subprocess
# from PIL import Image
import io


from scapy.all import *
from scapy.contrib import mqtt
#import pyfiglet
import matplotlib.pyplot as plt
import matplotlib.cm as cm
import numpy as np
#import hexdump
import os, time, subprocess
import shutil
from Pcap3Rules import Pcap3Rules
from datetime import datetime, date

# Usage: SplitCap [OPTIONS]...
#
# OPTIONS:
# -r <input_file> : Set the pcap file to read from
# -o <output_directory> : Manually specify output directory
# -d : Delete previous output data
# -p <nr_parallel_sessions> : Set the number of parallel sessions to keep in memory (default = 10000). More sessions might be needed to split pcap files from busy links such as an Internet backbone link, this will however require more memory
# -b <file_buffer_bytes> : Set the number of bytes to buffer for each session/output file (default = 10000). Larger buffers will speed up the process due to fewer disk write operations, but will occupy more memory.
# -s <GROUP> : Split traffic and group packets to pcap files based on <GROUP>. Possible values for <GROUP> are:
#   flow : Each flow, i.e. unidirectional traffic for a 5-tuple, is grouped
#   host : Traffic grouped to one file per host. Most packets will end up in two files.
#   hostpair : Traffic grouped based on host-pairs communicating
#   nosplit : Do not split traffic. Only create ONE output pcap.
#   (default) session : Packets for each session (bi-directional flow) are grouped
# -ip <IP address to filter on>
# -port <port number to filter on>
# -y <FILETYPE> : Output file type for extracted data. Possible values for <FILETYPE> are:
#   L7 : Only store application layer data
#   (default) pcap : Store complete pcap frames
#
# Example 1: SplitCap -r dumpfile.pcap
# Example 2: SplitCap -r dumpfile.pcap -o session_directory
# Example 3: SplitCap -r dumpfile.pcap -s hostpair
# Example 4: SplitCap -r dumpfile.pcap -s flow -y L7
# Example 5: SplitCap -r dumpfile.pcap -ip 1.2.3.4 -port 80 -port 443 -s nosplit

"""
def split_by_session(pcap_path: str):
    args = ("SplitCap/SplitCap.exe", "-r", pcap_path, "-s", "session")
    return execute(args).decode()


def split_by_host(pcap_path: str):
    args = ("SplitCap/SplitCap.exe", "-r", pcap_path, "-s", "host")
    return execute(args).decode()


def execute(args):
    popen = subprocess.Popen(args, stdout=subprocess.PIPE)
    popen.wait()
    return popen.stdout.read()
"""

if __name__ == '__main__':
    # split_by_session('IoT_Keylogging__00003_20180619141524.pcap')
    # split_by_host('IoT_Keylogging__00003_20180619141524.pcap')

    def menu():
        ########################## HELLO #############################
        """ascii_banner = pyfiglet.figlet_format("Pyotidsai!!")
        print(ascii_banner)"""
        print(""" 
                                                                                        
                                  mm      db        7MM                     db  
                                  MM                 MM                         
`7MMpdMAo. `7M'   `MF' ,pW"Wq.  mmMMmm  `7MM    ,M""bMM  ,pP"Ybd  ,6"Yb.   7MM  
  MM   `Wb   VA   ,V  6W'   `Wb   MM      MM  ,AP    MM  8I   `" 8)   MM    MM  
  MM    M8    VA ,V   8M     M8   MM      MM  8MI    MM  `YMMMa.  ,pm9MM    MM  
  MM   ,AP     VVV    YA.   ,A9   MM      MM  `Mb    MM  L.   I8 8M   MM    MM  
  MMbmmd'      ,V      `Ybmd9'    `Mbmo .JMML. `Wbmd"MML.M9mmmP' `Moo9^Yo..JMML.
  MM          ,V                                                                
.JMML.     OOb"                                                                 

Version: 1.1   Autor: Paloma Sánchez y Juan Pablo Egido   OS: Linux/Debian
""")

        ######################### MENU ############################
        print("\n [!] Bienvenid@ a Pyotidsai.")
        print('\n [!] Introduce la opción deseada '
              '\n [!] (1) Crear reglas'
              '\n [!] (2) Detectar malware(SNORT)'
              '\n [!] (0) Salir')


    def snort():
        if informacion == "s" or informacion == "S":
            os.system("stdbuf -o0 snort -A console --daq dump -q -c Snort/snort.conf -i eth0")
        else:
            a = subprocess.Popen("stdbuf -o0 snort -A console --daq dump -q -c Snort/snort.conf -i eth0".split(),stdout=subprocess.PIPE, bufsize=1)
            for output in a.stdout:
                # print(str(output))
                if 'NMAP' in output.decode("utf-8"):
                    print("({0}) Ataque de NMAP detectado".format(date.today()))
                    os.system('notify-send "Pyotidsai" "Ataque de NMAP detectado"')
                if 'SNMP' in output.decode("utf-8"):
                    print("({0}) Ataque via SNMP - Posible escaneo de puertos".format(date.today()))
                    os.system('notify-send "Pyotidsai" "Posible escaneo de puertos"')
                if 'ICMP PING' in output.decode("utf-8"):
                    print("({0}) Peticiones de ICMP".format(date.today()))
                    os.system('notify-send "Pyotidsai" "Peticiones de ICMP"')
                if 'ICMP Echo Reply' in output.decode("utf-8"):
                    print("({0}) Respuesta ICMP".format(date.today()))
                    os.system('notify-send "Pyotidsai" "Respuesta ICMP"')
                if 'DDOS mstream client to handler' in output.decode("utf-8"):
                    print("({0}) Ataque DOS mstream cliente a escucha - (Se esta recibiendo muchos paquetes)".format(date.today()))
                    os.system('notify-send "Pyotidsai" "Ataque DOS mstream cliente a escucha"')
                if 'BAD-TRAFFIC' in output.decode("utf-8"):
                    print("[!] Buscando paquetes")
                if 'ARP' in output.decode("utf-8"):
                    print("[!] Posible ataque ARP detectado")
                    os.system('notify-send "Pyotidsai" "Posible ataque ARP detectado"')
                if 'meterpreter' in output.decode("utf-8"):
                    print("[!] Conexion meterpreter detectada via UDP.")
                    os.system('notify-send "Pyotidsai" "Conexion meterpreter detectada"')
        print("[*] ERROR [*]")


    while True:
        menu()
        opt = input()
        pcap = ""
        if opt == '1':
                pcap = input('introduce pcap a analizar:')
                subprocess.run(["python", "Pcap3Rules/Pcap3Rules.py", "-r", pcap, "-s"])
                print('Finalizado. Se han creado las reglas.')
                ver = input('[!] ¿Desea ver las reglas creadas? [S/N]')
                if ver == 'S' or ver == 's':
                    with (open('snortRules.rules', 'r')) as file:
                        data = file.read()
                        print("\x1b[1;33m"+data+'\033[0;m')
                shutil.copy('snortRules.rules', 'Snort/rules')

        elif opt == '2':
            print("[!] Este programa esta creando un pcap en la misma ruta que Pyotidsai, [LOG]")
            print("[!] Estamos analizando los paquetes por posibles ataques\n")
            informacion = str(input("\n"+"\033[4;35m"+"[+] Desea ver informacion mas completa (snort) [S/N]: "+'\033[0;m'))
            snort()
        elif opt == '0':
            print('Hasta la próxima!!')
            break;
        else:
            print("")
            input("No has pulsado ninguna opción correcta...\npulsa una tecla para continuar")

    """
    
        sniff(offline=input(), lfilter=lambda x: "TCP" in x, prn=lambda x: print("Alerta!!" + x.summary()) if (
                x["IP"].src == "192.168.100.3" and (x["IP"].dst != "192.168.1.1")) else None)
        ####################### pcap->binary->image ###################
        try:
            with (open('test.pcap', 'br')) as file:
                data = file.read()
                print(hexdump(data, 'b'))

            # delete first colum binaryPcap
            f = open('binaryPcap', 'r')
            fnew = open('binaryNewPcap.txt', 'w')
            for line in f.readlines():
                line = line[10:71]
                fnew.writelines(line + '\n')
            # Draw
            data_set = np.loadtxt('p.txt')
            data_array = np.vstack(data_set)
            fig = plt.figure(figsize=(25, 35))
            fig.add_subplot(111)
            plt.imshow(data_array, cmap='Greys', interpolation='nearest')
            plt.savefig("image.png", bbox_inches='tight', dpi=100)
            plt.show()
            plt.close()


        except Exception as e:
            print(e)
        """
