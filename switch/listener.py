#!/usr/bin/env python
import sys
import struct
import argparse
import commands

from scapy.all import sniff, sendp, hexdump, get_if_list, get_if_hwaddr
from scapy.all import Packet, IPOption
from scapy.all import IP, TCP, ICMP, UDP, Raw 

parser = argparse.ArgumentParser(description='P4 Controller')
parser.add_argument('-p', '--port', help='listen port', 
                    type=str, action="store", default='s1-eth3')
args = parser.parse_args()

tcp_counter = 0
udp_counter = 0
icmp_counter = 0

def handle_tcp_pkt(packet):
    global tcp_counter
    tcp_counter = tcp_counter+1
    return 'TCP Packet #{}: {} ==> {}, sport {} ==> dport {}'.format(tcp_counter, packet[0][1].src, packet[0][1].dst, packet[TCP].sport, packet[TCP].dport)

def handle_udp_pkt(packet):
    global udp_counter
    udp_counter = udp_counter+1
    return 'UDP Packet #{}: {} ==> {}, sport {} ==> dport {}'.format(udp_counter, packet[0][1].src, packet[0][1].dst, packet[UDP].sport, packet[UDP].dport)

def handle_icmp_pkt(packet):
    global icmp_counter
    icmp_counter = icmp_counter+1
    return 'ICMP Packet #{}: {} ==> {}'.format(icmp_counter, packet[0][1].src, packet[0][1].dst)

def handle_pkt(packet):
    if packet.haslayer(TCP) == 1:
        return handle_tcp_pkt(packet)
    elif packet.haslayer(UDP) == 1:
        return handle_udp_pkt(packet)
    elif packet.haslayer(ICMP) == 1:
        return handle_icmp_pkt(packet)
    else:
        return "Got an unexcepted packet"

def main():
    iface = args.port
    print "sniffing on %s" % iface
    sys.stdout.flush()
    sniff(filter="ip", iface = iface, prn = lambda x: handle_pkt(x))

if __name__ == '__main__':
    main()
