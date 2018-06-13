#!/usr/bin/env python

import argparse
import sys
import socket
import random
import struct

from scapy.all import *
from time import sleep

parser = argparse.ArgumentParser(description='Generating random flows')
parser.add_argument('-n', '--num', help='total number', 
                    type=int, action="store", default=100)
parser.add_argument('-i', '--iface', help='Interface', 
                    type=str, action="store", default='s1-eth1')
args = parser.parse_args()

def TCPPacket(dl_src, dl_dst, nw_src, nw_dst, nw_proto, srcPort, dstPort, seqNum):
    return Ether(src=dl_src, dst=dl_dst) / IP(src=nw_src, dst=nw_dst) / TCP(sport=srcPort, dport=dstPort, seq=seqNum) 

def UDPPacket(dl_src, dl_dst, nw_src, nw_dst, nw_proto, srcPort, dstPort):
    return Ether(src=dl_src, dst=dl_dst) / IP(src=nw_src, dst=nw_dst) / UDP(sport=srcPort, dport=dstPort) 

def main():
    dl_src = '00:00:00:00:00:01'
    dl_dst = '00:00:00:00:00:02'
    num, iface = args.num, args.iface

    for i in range(num):
        proto = random.randint(1, 2)
        nw_src, nw_dst = "", ""
        srcIdx1, dstIdx1 = random.randint(1, 255), random.randint(1, 255)
        srcIdx2, dstIdx2 = random.randint(1, 255), random.randint(1, 255)
        srcIdx3, dstIdx3 = random.randint(1, 255), random.randint(1, 255)
        srcIdx4, dstIdx4 = random.randint(1, 255), random.randint(1, 255)
        nw_src = str(srcIdx1)+'.'+str(srcIdx2)+'.'+str(srcIdx3)+'.'+str(srcIdx4)
        nw_dst = str(dstIdx1)+'.'+str(dstIdx2)+'.'+str(dstIdx3)+'.'+str(dstIdx4)
        srcPort, dstPort = random.randint(0, 65535), random.randint(0, 65535)
        
        if proto == 1:
            nw_proto = 6
            pkt = TCPPacket(dl_src, dl_dst, nw_src, nw_dst, nw_proto, srcPort, dstPort, i)
        elif proto == 2:
            nw_proto = 17
            pkt = UDPPacket(dl_src, dl_dst, nw_src, nw_dst, nw_proto, srcPort, dstPort)
        else:
            break

        sendp(pkt, iface=iface, verbose=0)

if __name__ == '__main__':
    main()