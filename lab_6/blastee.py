#!/usr/bin/env python3

from switchyard.lib.address import *
from switchyard.lib.packet import *
from switchyard.lib.userlib import *
from threading import *
import time

def switchy_main(net):
    my_interfaces = net.interfaces()
    mymacs = [intf.ethaddr for intf in my_interfaces]

    with open("blastee_params.txt") as file_object:
        info = file_object.read()
        info = info.split()

    while True:
        gotpkt = True
        try:
            timestamp,dev,pkt = net.recv_packet()
            log_debug("Device is {}".format(dev))
        except NoPackets:
            log_debug("No packets available in recv_packet")
            gotpkt = False
        except Shutdown:
            log_debug("Got shutdown signal")
            break

        if gotpkt:
            log_debug("I got a packet from {}".format(dev))
            #log_info("Pkt: {}".format(pkt))

            if not pkt.has_header(Arp):
                ack = Ethernet() + IPv4() + UDP()
                ack[0].src = '20:00:00:00:00:01'
                ack[0].dst = '40:00:00:00:00:02'
                ack[1].src = '192.168.200.1'
                ack[1].dst = '192.168.100.1'
                ack[1].protocol = IPProtocol.UDP
                ack[1].ttl = 10
                # 添加序列号
                ack += pkt[3].to_bytes()[:4]
                # 解析payload的长度
                length = int.from_bytes(pkt[3].to_bytes()[4:6], 'big')
                '''
                seq = int.from_bytes(pkt[3].to_bytes()[:4], 'big')
                print(seq)
                '''
                # 根据payload长度确定是否要补齐
                if length >= 8:
                    ack += pkt[3].to_bytes()[6:14]
                else:
                    ack += pkt[3].to_bytes()[6:]
                    ack += (0).to_bytes(8 - length, "big")
                net.send_packet(dev, ack)

    net.shutdown()
