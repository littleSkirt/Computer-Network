# -*- coding: utf-8 -*-

from scapy.all import *
from collections import OrderedDict
import matplotlib.pyplot as plt
from scapy.layers.inet import TCP,IP
from scapy.layers.inet6 import IPv6

conf.verb = 0
def packet_info(pcap_file, save_file):
    connections = OrderedDict()
    # :return: not specified
    packets = rdpcap(pcap_file)
    acks = OrderedDict()
    for packet in packets:
        if 'IP' in packet and 'TCP' in packet:
            # Extract source and destination IP addresses
            src_ip = packet['IP'].src
            dst_ip = packet['IP'].dst
            # Extract source and destination port numbers
            src_port = packet['TCP'].sport
            dst_port = packet['TCP'].dport
            key = (src_ip, src_port, dst_ip, dst_port)
            if key not in connections:
                connections[key] = []
            connections[key].append(packet)
    # graph_analyer(connections)
    with open(save_file, 'w') as f:
        for conn in connections:
            # f.write(f'{src_ip}:{src_port} -> {dst_ip}:{dst_port}\n')
            f.write(f'{conn[0]}:{conn[1]} -> {conn[2]}:{conn[3]}\n')

def GET_seqnum(packets, client_ip, server_ip, client_port, server_port):
    cISN, sISN = 0, 0
    for packet in packets:
        src_ip, dst_ip, src_port, dst_port = GET_four(packet)
        if (src_ip, dst_ip, src_port, dst_port) == (client_ip, server_ip, client_port, server_port) and packet['TCP'].flags & 0x002:
            cISN = packet['TCP'].seq
        elif (src_ip, dst_ip, src_port, dst_port) == (server_ip, client_ip, server_port, client_port) and packet['TCP'].flags & 0x002:
            sISN = packet['TCP'].seq
        if cISN and sISN:
            break
    return cISN, sISN
def GET_four(packet):
    if packet.haslayer('IPv6'):
        src_ip = packet['IPv6'].src
        dst_ip = packet['IPv6'].dst
        src_port = packet['TCP'].sport
        dst_port = packet['TCP'].dport
    elif packet.haslayer('IP'):
        src_ip = packet['IP'].src
        dst_ip = packet['IP'].dst
        src_port = packet['TCP'].sport
        dst_port = packet['TCP'].dport
    return src_ip, dst_ip, src_port, dst_port
def tcp_stream_analyzer(file, savefile, client_ip_prev, server_ip_prev, client_port_prev, server_port_prev):
    pool= []
    key_prev = (server_ip_prev, server_port_prev, client_ip_prev, client_port_prev)
    packets = rdpcap(file)
    cISN,sISN = GET_seqnum(packets, client_ip_prev, server_ip_prev, client_port_prev, server_port_prev)
    for packet in packets:
        src_ip, dst_ip, src_port, dst_port = GET_four(packet)
        if (src_ip, src_port) == (client_ip_prev, client_port_prev) and (dst_ip, dst_port) == (server_ip_prev, server_port_prev):
            pkt_sender = 'Client'
            pkt_receiver = 'Server'
            seq_num = packet['TCP'].seq - cISN
            ack_num = max(packet['TCP'].ack - sISN, 0)
        elif (src_ip, src_port) == (server_ip_prev, server_port_prev) and (dst_ip, dst_port) == (client_ip_prev, client_port_prev):
            pkt_sender = 'Server'
            pkt_receiver = 'Client'
            seq_num = packet['TCP'].seq - sISN
            ack_num = max(packet['TCP'].ack - cISN, 0)
        else:
            continue
        flag = ""
        if packet['TCP'].flags & 0x01: flag += "F"
        if packet['TCP'].flags & 0x02: flag += "S"
        if packet['TCP'].flags & 0x04: flag += "R"
        if packet['TCP'].flags & 0x08: flag += "P"
        if packet['TCP'].flags & 0x10: flag += "A"
        if packet['TCP'].flags & 0x20: flag += "U"
        if packet['TCP'].flags & 0x40: flag += "E"
        if packet['TCP'].flags & 0x80: flag += "C"
        flag = packet.sprintf('%TCP.flags%')
        pkt = {'pkt_sender': pkt_sender, 'pkt_receiver': pkt_receiver, 'seq_num': seq_num, 'ack_num': ack_num,
               'flags': flag, 'time': packet.time}
        pool.append(pkt)

    with open(savefile, 'w') as f:
        ss = f'Server : {server_ip_prev}:{server_port_prev} <-> Client : {client_ip_prev}:{client_port_prev} \n'
        print(ss)
        f.write(ss)
        for i, pkt in enumerate(sorted(pool, key=lambda x: x['time'])):
            s = f"{pkt['pkt_sender']} -> {pkt['pkt_receiver']} Num: {i+1}, SEQ: {pkt['seq_num']}, ACK: {pkt['ack_num']} {pkt['flags']}\n"
            print(s)
            f.write(s)

def http_stream_analyzer(pcapfile, savefile, client_ip_prev, server_ip_prev, client_port_prev):
    packets = rdpcap(pcapfile)
    key = (client_ip_prev,server_ip_prev,client_port_prev)
    with open(savefile, 'w') as f:
        for packet in packets:
            # packet.show()
            srcIP = packet['IP'].src
            dstIP = packet['IP'].dst
            srcPort = packet['TCP'].sport
            dstPort = packet['TCP'].dport
            key1 = (srcIP,dstIP,srcPort)
            key2 = (dstIP,srcIP,dstPort)
            if key1 == key:
                try:
                    http = packet.getlayer(TCP).payload
                    httpSTR = str(http)
                    httpSTR = httpSTR.replace("b'","").replace("'","")
                    # print(httpSTR)
                    name = httpSTR.split("\\r\\n")[0]
                    if name.startswith('HTTP/1.1'):
                        f.write(f'{name}\n')
                    elif name.startswith('GET'):
                        f.write(f'{name}\n')
                    else:
                        f.write(f'..NO HEADER..\n')
                except:
                    f.write(f'..NO HEADER..\n')
                    continue
            if key2 == key:
                try:
                    http = packet.getlayer(TCP).payload
                    httpSTR = str(http)
                    httpSTR = httpSTR.replace("b'","").replace("'","")
                    # print(httpSTR)
                    name = httpSTR.split("\\r\\n")[0]
                    if name.startswith('HTTP/1.1'):
                        f.write(f'{name}\n')
                    elif name.startswith('GET'):
                        f.write(f'{name}\n')
                    else:
                        f.write(f'..NO HEADER..\n')
                except:
                    f.write(f'..NO HEADER..\n')
                    continue
def graph_analyer(pcap_file):
    packets = rdpcap(pcap_file)
    index = 0
    ackss = ()
    acknum = 0
    for packet in packets:
        index+=1
        if 'IP' in packet and 'TCP' in packet:
            num = packet['TCP'].ack
            ackss = ackss+(num,)
        if index==500:
            break
    # Create x-axis values (just the index of each ACK)
    x_values = list(range(len(ackss)))
    # Plot the line chart
    plt.plot(x_values, ackss)
    # Add x and y labels and a title
    plt.xlabel('Packet Number')
    plt.ylabel('ACK Number')
    plt.title('ACK Numbers vs Packet Numbers')
    # Show the plot
    plt.show()

if __name__ == '__main__':
    # pcap_file = r"D:\PyCharm Community Edition 2021.3.1\python_projects\Computer_Network\PA2\TCP_PKTS.pcap"
    # pcap_file = r"D:\PyCharm Community Edition 2021.3.1\python_projects\Computer_Network\PA2\tcp1.pcap"
    # graph_analyer(pcap_file)
    # pcap_file = r"D:\PyCharm Community Edition 2021.3.1\python_projects\Computer_Network\PA2\tcp2.pcap"
    # graph_analyer(pcap_file)
    pcap_file = r"D:\PyCharm Community Edition 2021.3.1\python_projects\Computer_Network\PA2\tcp3.pcap"
    # graph_analyer(pcap_file)
    # pcap_file = r"D:\PyCharm Community Edition 2021.3.1\python_projects\Computer_Network\PA2\tcp.pcapng"
    # pcap_file = r"D:\PyCharm Community Edition 2021.3.1\python_projects\Computer_Network\PA2\tcp5.pcap"
    graph_analyer(pcap_file)
    # pcap_file = r"D:\PyCharm Community Edition 2021.3.1\python_projects\Computer_Network\PA2\HTTP_.pcap"  # :param pcap_file: path to pcap file
    # save_file = r"D:\PyCharm Community Edition 2021.3.1\python_projects\Computer_Network\PA2\PACKET_INFOhi.txt" # :param save_file: path to save file of results
    # packet_info(pcap_file, save_file)

    # save_file = r"D:\PyCharm Community Edition 2021.3.1\python_projects\Computer_Network\PA2\tcp.txt"
    # tcp_stream_analyzer(pcap_file, save_file,'113.240.72.12','10.26.184.140', '8081', '1310')
    # tcp_stream_analyzer(pcap_file, save_file, 1, 1, 1, 1)
    # # tcp_stream_analyzer1(pcap_file, save_file,'113.240.72.12','10.26.184.140', '8081', '1310')
    # tcp_stream_analyzer(pcap_file, save_file, 1, 1, 1, 1)
    # tcp_stream_analyzer(pcap_file, save_file, 1, 1, 1, 1)
    # tcp_stream_analyzer(pcap_file, save_file, '10.26.184.140', '113.240.72.12', '1310', '8081')
    # tcp_stream_analyzer(pcap_file, save_file, 1, 1, 1, 1)
    # # tcp_stream_analyzer1(pcap_file, save_file, '10.26.184.140', '113.240.72.12', '1310', '8081')
    # tcp_stream_analyzer(pcap_file, save_file, 1, 1, 1, 1)
    # tcp_stream_analyzer(pcap_file, save_file, 1, 1, 1, 1)
    # tcp_stream_analyzer(pcap_file, save_file, '2001:da8:201d:1109::1321', '240e:ff:f101:10::1a0', '1313', '443')
    # tcp_stream_analyzer(pcap_file, save_file, 1, 1, 1, 1)
    # # tcp_stream_analyzer1(pcap_file, save_file, '2001:da8:201d:1109::1321', '240e:ff:f101:10::1a0', '1313', '443')
    # tcp_stream_analyzer(pcap_file, save_file, 1, 1, 1, 1)
    # tcp_stream_analyzer(pcap_file, save_file, 1, 1, 1, 1)
    # tcp_stream_analyzer(pcap_file, save_file, '240e:ff:f101:10::1a0','2001:da8:201d:1109::1321', '443',  '1313')
    # tcp_stream_analyzer(pcap_file, save_file, 1, 1, 1, 1)
    # # tcp_stream_analyzer1(pcap_file, save_file, '240e:ff:f101:10::1a0','2001:da8:201d:1109::1321', '443',  '1313')
    # tcp_stream_analyzer(pcap_file, save_file, 1, 1, 1, 1)
    # tcp_stream_analyzer(pcap_file, save_file, 1, 1, 1, 1)
    # tcp_stream_analyzer(pcap_file, save_file, '10.25.217.154',' 113.246.57.9','53560' ,'80')
    # tcp_stream_analyzer(pcap_file, save_file, 1, 1, 1, 1)
    # tcp_stream_analyzer1(pcap_file, save_file, '10.25.217.154',' 113.246.57.9','53560' ,'80')
    # tcp_stream_analyzer(pcap_file, save_file, 1, 1, 1, 1)
    # tcp_stream_analyzer(pcap_file, save_file, 1, 1, 1, 1)
    # # save_file = r"D:\PyCharm Community Edition 2021.3.1\python_projects\Computer_Network\PA2\tcp2.txt"
    # tcp_stream_analyzer(pcap_file,save_file, '10.26.184.140', '169.254.169.254', 1294, 80)
    # tcp_stream_analyzer(pcap_file, save_file, 1, 1, 1, 1)
    # tcp_stream_analyzer1(pcap_file,save_file, '10.26.184.140', '169.254.169.254', 1294, 80)

    # save_file = r"D:\PyCharm Community Edition 2021.3.1\python_projects\Computer_Network\PA2\http.txt"
    # http_stream_analyzer(pcap_file, save_file, '10.25.217.154', '113.246.57.9', 53560)

