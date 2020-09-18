#!/usr/bin/env python3

from switchyard.lib.address import *
from switchyard.lib.packet import *
from switchyard.lib.userlib import *
from random import randint
import time


def switchy_main(net):
    my_intf = net.interfaces()
    mymacs = [intf.ethaddr for intf in my_intf]
    myips = [intf.ipaddr for intf in my_intf]

    with open("blaster_params.txt") as file_object:
        info = file_object.read()
        info = info.split()
    
    # 解析参数
    recv_to = int(info[-1]) / 1000
    length = int(info[5])
    num = int(info[3])
    timeout = int(info[-3]) / 1000
    sw = int(info[-5])
    # 设置状态判断参数、数组以及统计数据等
    ackd = [0 for i in range(num + 1)]
    sent = [0 for i in range(num + 1)]
    ackednum = 0
    retran = False
    retranpoint = 0
    retrannum = 0
    LHS = RHS = 1
    begintime = timer = time.time()
    coarsenum = 0
    throughput = 0
    goodput = 0

    while True:
        gotpkt = True
        try:
            #Timeout value will be parameterized!
            timestamp, dev, pkt = net.recv_packet(timeout=recv_to)
        except NoPackets:
            log_debug("No packets available in recv_packet")
            gotpkt = False
        except Shutdown:
            log_debug("Got shutdown signal")
            break

        if gotpkt:
            log_debug("I got a packet")
            #log_info("Pkt: {}".format(pkt))
            if not pkt.has_header(Arp):
                # 解析序列号
                data = pkt[3].to_bytes()[:4]
                seq = int.from_bytes(data, 'big')
                # print("get", seq)
                if ackd[seq] == 0:
                    ackednum += 1
                ackd[seq] = 1
                # 判断是否所有包都收到ACK
                if ackednum == num:
                    endtime = time.time()
                    break
                # 将LHS右移至第一个未收到ACK的包并重置计时器
                while ackd[LHS] == 1:
                    LHS += 1
                    timer = time.time()
                
        else:
            log_debug("Didn't receive anything")

        '''
        Creating the headers for the packet
        '''
        pkt = Ethernet() + IPv4() + UDP()
        pkt[1].protocol = IPProtocol.UDP

        '''
        Do other things here and send packet
        '''
        pkt[0].src = '10:00:00:00:00:01'
        pkt[0].dst = '40:00:00:00:00:01'
        pkt[1].src = '192.168.100.1'
        pkt[1].dst = '192.168.200.1'
        pkt[1].ttl = 10
        # 发生超时
        if time.time() - timer > timeout:
            # print("time out")
            retran = True
            # retranend = RHS
            coarsenum += 1
            # 从LHS开始重传
            retranpoint = LHS
            # print("retran", retranpoint)
            # print("LHS", LHS, "RHS", RHS)
            data = retranpoint.to_bytes(4, 'big')
            data += length.to_bytes(2, 'big')
            pkt += data
            pkt += 'retran'.ljust(length, '.').encode()
            net.send_packet('blaster-eth0', pkt)
            throughput += length
            # 重置计时器
            timer = time.time()
            # 重传指向下一个包
            retranpoint += 1
            retrannum += 1
        else:
            # 处于重传状态中
            if retran and retranpoint <= RHS and retranpoint != 0:
                # 从当前指向的包开始找到第一个未ACK的包
                while retranpoint < num and ackd[retranpoint] == 1:
                    retranpoint += 1
                # 滑动窗口中存在未ACK的包
                if retranpoint <= RHS and ackd[retranpoint] == 0:
                    # print("LHS", LHS, "RHS", RHS)
                    data = retranpoint.to_bytes(4, 'big')
                    data += length.to_bytes(2, 'big')
                    pkt += data
                    if sent[retranpoint] == 1:
                        pkt += 'retran'.ljust(length, '.').encode()
                        retrannum += 1
                        # print("retran", retranpoint)
                    # 处于重传队列但是第一次发送的包
                    else:
                        pkt += 'hello'.ljust(length, '.').encode()
                        goodput += length
                        # print("retran send", retranpoint)
                        sent[retranpoint] = 1
                    net.send_packet('blaster-eth0', pkt)
                    throughput += length
                    # 窗口内所有未ACK的包都ACK后结束重传状态
                    if retranpoint == RHS:
                        retran = False
                    retranpoint += 1
                else:
                    retran = False      # 滑动窗口中不存在未ACK的包
            # 窗口大小未超过限制
            elif RHS - LHS + 1 <= sw:
                # 窗口中最后一个包还未发送
                if sent[RHS] == 0:
                    # print("send", RHS)
                    data = RHS.to_bytes(4, 'big')
                    data += length.to_bytes(2, 'big')
                    pkt += data
                    pkt += 'hello'.ljust(length, '.').encode()
                    net.send_packet('blaster-eth0', pkt)
                    throughput += length
                    goodput += length
                    sent[RHS] = 1
                    # 窗口大小未达到限制且未超过包总数，可以扩张
                    if RHS - LHS + 1 < sw and RHS < num:
                        RHS += 1
                # 窗口中最后一个包已发送，但大小未达到限制且未超过包总数，可以扩张
                elif RHS - LHS + 1 < sw and RHS < num:
                    RHS += 1
        # print("LHS", LHS, "RHS", RHS)

            
    net.shutdown()
    print("Total TX time:", endtime - begintime)
    print("Number of reTX:", retrannum)
    print("Number of coarse TOs:", coarsenum)
    print("Throughput (Bps):",  throughput / (endtime - begintime))
    print("Goodput (Bps):", goodput / (endtime - begintime))
