import subprocess
# from PIL import Image
import io
from scapy.all import *
from scapy.contrib import mqtt
import pyfiglet
import matplotlib.pyplot as plt
import matplotlib.cm as cm
import numpy as np
import hexdump

from Pcap3Rules import Pcap3Rules



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


if __name__ == '__main__':
    # split_by_session('IoT_Keylogging__00003_20180619141524.pcap')
    # split_by_host('IoT_Keylogging__00003_20180619141524.pcap')


    ########################## HELLO #############################
    ascii_banner = pyfiglet.figlet_format("Pyotidsai!!")
    print(ascii_banner)
    ######################### Options ############################
    print('Introduce la opción deseada '
          '\n(1) Seleccionar pcap'
          '\n(2) Crear reglas'
          '\n(3) Detectar malware(SNORT)')
    opt = input()
    if (opt == '1'):
        pcap = input('introduce pcap a analizar:')
    if (opt == '2'):
        args = ("python","Pcap3Rules/Pcap3Rules.py", "-r", pcap, "-s")
        execute(args).decode()
        print('Finalizado')
    if (opt == '3'):
        print('holi')


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
