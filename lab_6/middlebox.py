#!/usr/bin/env python3

from switchyard.lib.address import *
from switchyard.lib.packet import *
from switchyard.lib.userlib import *
from threading import *
from random import randint
from random import random
import time

def switchy_main(net):

    my_intf = net.interfaces()
    mymacs = [intf.ethaddr for intf in my_intf]
    myips = [intf.ipaddr for intf in my_intf]

    # 从文件中读取丢包率
    with open("middlebox_params.txt") as file_object:
        info = file_object.read()
        info = info.split()
    drop_rate = float(info[1])

    drop = 0    # 统计丢包数

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
            log_debug("I got a packet {}".format(pkt))

        if dev == "middlebox-eth0":
            log_debug("Received from blaster")
            '''
            Received data packet
            Should I drop it?
            If not, modify headers & send to blastee
            '''
            # 生成随机数并判断是否丢包
            rand = random()
            if rand > drop_rate:
                pkt[0].src = '40:00:00:00:00:02'
                pkt[0].dst = '20:00:00:00:00:01'
                net.send_packet("middlebox-eth1", pkt)
            else:
                drop += 1
        
        elif dev == "middlebox-eth1":
            log_debug("Received from blastee")
            '''
            Received ACK
            Modify headers & send to blaster. Not dropping ACK packets!
            net.send_packet("middlebox-eth0", pkt)
            '''
            pkt[0].src = '40:00:00:00:00:01'
            pkt[0].dst = '10:00:00:00:00:01'
            net.send_packet("middlebox-eth0", pkt)
        else:
            log_debug("Oops :))")
    #print("lost", drop)
    net.shutdown()
