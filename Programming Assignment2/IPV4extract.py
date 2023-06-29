from scapy.all import *
from collections import OrderedDict

# Read pcap file
pkts = rdpcap('TCP_PKTS.pcap')

# Create an ordered dictionary to store connections
connections = OrderedDict()

# Iterate through each packet in the pcap file
for pkt in pkts:
    # Check if it is an IPv4/TCP packet
    if IP in pkt and TCP in pkt:
        # Extract source and destination IP addresses
        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst

        # Extract source and destination port numbers
        src_port = pkt[TCP].sport
        dst_port = pkt[TCP].dport

        # Check if the connection already exists in the dictionary
        if (dst_ip, src_ip, dst_port, src_port) in connections:
            # If yes, append the packet to the existing connection
            connections[(dst_ip, src_ip, dst_port, src_port)].append(pkt)
        else:
            # If no, create a new connection with the packet
            connections[(src_ip, dst_ip, src_port, dst_port)] = [pkt]

# Open the output file in write mode
with open('PACKET_INFO.txt', 'w') as f:
    # Iterate through each connection in the dictionary
    for conn in connections:
        # Print the connection details to console
        print(f'{conn[0]}:{conn[2]} -> {conn[1]}:{conn[3]}')

        # Write the connection details to file
        f.write(f'{conn[0]}:{conn[2]} -> {conn[1]}:{conn[3]}\n')

        # Iterate through each packet in the connection and write it to file
        # for pkt in connections[conn]:
        #     f.write(f'{pkt.time}\n')

    print('Output written to PACKET_INFO.txt')
