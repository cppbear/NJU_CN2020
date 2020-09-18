#!/usr/bin/env python3

'''
Basic IPv4 router (static routing) in Python.
'''

import sys
import os
import time
from switchyard.lib.userlib import *


class Wait:
    def __init__(self, pkt, intf, dstip):
        self.packet = pkt
        self.lasttime = 0   # 上一次发送ARP请求的时间
        self.count = 0      # 累计发送ARP请求的次数
        self.interface = intf
        self.dstipaddr = dstip

    def forwarding(self, cache, net, repeat):
        if self.dstipaddr in cache.keys():
            # ARP缓存表中有匹配则替换相应地址后发送
            dstmac = cache[self.dstipaddr]
            self.packet[0].dst = str(dstmac)
            net.send_packet(self.interface.name, self.packet)
            return 0
        # 需要距离上次发送超过1秒且相同的目的地址还没发送过请求
        elif time.time() - self.lasttime >= 1 and self.dstipaddr not in repeat:
            if self.count < 5:          # 且发送次数不超过5次
                repeat.append(self.dstipaddr)
                # 构建ARP请求包，发送并更新状态
                ether = Ethernet()
                # ether.src = self.packet[0].src
                ether.src = self.interface.ethaddr
                ether.dst = 'ff:ff:ff:ff:ff:ff'
                ether.ethertype = EtherType.ARP
                arp = Arp(operation=ArpOperation.Request,
                          senderhwaddr=self.interface.ethaddr,
                          senderprotoaddr=self.interface.ipaddr,
                          targethwaddr='ff:ff:ff:ff:ff:ff',
                          targetprotoaddr=self.dstipaddr)
                arppacket = ether + arp
                self.lasttime = time.time()
                net.send_packet(self.interface.name, arppacket)
                self.count += 1
                return 1
            else:
                return - 1
        else:
            return 1

class Router(object):
    def __init__(self, net):
        self.net = net
        # other initialization stuff here

    def icmperr(self, inter, pkt, xtype, code):
        packet = Ethernet() + IPv4() + ICMP()
        # packet[0].src = inter.ethaddr
        packet[1].dst = pkt[1].src
        packet[1].src = inter.ipaddr
        packet[1].ttl = 10
        packet[2].icmptype = xtype
        packet[2].icmpcode = code
        xpkt = deepcopy(pkt)
        i = xpkt.get_header_index(Ethernet)
        if i >= 0:
            del xpkt[i]
        packet[2].icmpdata.data = xpkt.to_bytes()[:28]
        packet[2].icmpdata.origdgramlen = len(xpkt)
        return packet

    def prefixmatch(self, forwarding_table, ipdst):
        net = IPv4Network('0.0.0.0/0')
        prefix = 0
        for key in forwarding_table.keys():
            if ipdst in key:
                if key.prefixlen > prefix:
                    net = key
                    prefix = key.prefixlen
        return net, prefix

    def router_main(self):
        '''
        Main method for router; we stay in a loop in this method, receiving
        packets until the end of time.
        '''
        
        cache = {}
        forwarding_table = {}
        waiting_queue = []
        
        my_interfaces = self.net.interfaces()
        for intf in my_interfaces:
            # print(intf)
            ipaddr = IPv4Address(int(intf.ipaddr) & int(intf.netmask))  # 通过掩码取出端口的IP地址所在的子网
            key = IPv4Network(str(ipaddr) + '/' + str(intf.netmask))    # 子网地址与掩码组合形成键
            forwarding_table[key] = ['', intf.name]                     # 下一跳地址用空字符''代替

        with open("forwarding_table.txt") as file_object:
            for line in file_object:
                info = line.rsplit()        # 去掉行尾回车
                if info:                    # 确保不是空行
                    key = IPv4Network(info[0] + '/' + info[1])  # 子网地址与掩码组合
                    forwarding_table[key] = info[2:]
        
        for item in forwarding_table.items():
            print(item)
        
        while True:
            gotpkt = True
            try:
                timestamp, dev, pkt = self.net.recv_packet(timeout=1.0)
            except NoPackets:
                log_debug("No packets available in recv_packet")
                gotpkt = False
            except Shutdown:
                log_debug("Got shutdown signal")
                break

            if gotpkt:
                log_debug("Got a packet: {}".format(str(pkt)))

                # 将非ARP和IPv4的包抛弃
                arp = pkt.get_header(Arp)
                ipv4 = pkt.get_header(IPv4)
                
                if arp:
                    # 更新ARP缓存表
                    cache[arp.senderprotoaddr] = arp.senderhwaddr
                    
                    for key, value in cache.items():
                        print(key, "\t", value)
                    print()
                    
                    if arp.operation == ArpOperation.Request:
                        for intf in my_interfaces:
                            if arp.targetprotoaddr == intf.ipaddr:
                                packet = create_ip_arp_reply(intf.ethaddr, arp.senderhwaddr, arp.targetprotoaddr, arp.senderprotoaddr)
                                self.net.send_packet(intf.name, packet)
                                log_debug("send packet {} to {}".format(packet, intf.name))
                elif ipv4:
                    # 准备转发数据包的预处理
                    prefix = 0
                    net = IPv4Network('0.0.0.0/0')
                    for intf in my_interfaces:
                        if pkt[1].dst == intf.ipaddr:
                            if pkt.has_header(ICMP) and pkt.get_header(ICMP).icmptype == 8:
                                # 响应ping路由器的包
                                # print("响应ping路由器的包")
                                icmp_index = pkt.get_header_index(ICMP)
                                icmp = pkt.get_header(ICMP)
                                icmp_reply = ICMP()
                                icmp_reply.icmptype = ICMPType.EchoReply
                                icmp_reply.icmpdata.sequence = icmp.icmpdata.sequence
                                icmp_reply.icmpdata.identifier = icmp.icmpdata.identifier
                                icmp_reply.icmpdata.data = icmp.icmpdata.data
                                pkt[1].dst = pkt[1].src
                                pkt[1].src = intf.ipaddr
                                pkt[icmp_index] = icmp_reply
                                break
                            else:
                                # 目标为路由器，但非ICMP
                                # print("目标为路由器，但非ICMP")
                                for intf in my_interfaces:
                                    if intf.name == dev:
                                        inter = intf
                                        break
                                pkt = self.icmperr(inter, pkt, ICMPType.DestinationUnreachable, 3)
                                break
                    
                    # 最长前缀匹配
                    net, prefix = self.prefixmatch(forwarding_table, pkt[1].dst)
                    # 匹配失败/目标网络不可达
                    if prefix == 0:
                        # print("匹配失败,目标网络不可达")
                        for intf in my_interfaces:
                            if intf.name == dev:
                                inter = intf
                                break
                        pkt = self.icmperr(inter, pkt, ICMPType.DestinationUnreachable, 0)
                        net, prefix = self.prefixmatch(forwarding_table, pkt[1].dst)
                    # 匹配成功
                    pkt[1].ttl -= 1
                        
                    # TTL超时
                    if pkt[1].ttl <= 0:
                        # print("TTL超时")
                        for intf in my_interfaces:
                            if intf.name == dev:
                                inter = intf
                                break
                        pkt = self.icmperr(inter, pkt, ICMPType.TimeExceeded, 0)
                        prefix = 0
                        net, prefix = self.prefixmatch(forwarding_table, pkt[1].dst)
                    # 确定下一跳地址
                    if forwarding_table[net][0]:
                        dstipaddr = IPv4Address(forwarding_table[net][0])
                    else:
                        dstipaddr = pkt[1].dst
                    # 找出转发端口
                    interface = forwarding_table[net][1]
                    for intf in my_interfaces:
                        if intf.name == interface:
                            router_intf = intf
                            break
                    pkt[0].src = router_intf.ethaddr
                    # 将数据包和端口、目标地址打包成一个类对象加入队列
                    waiting_queue.append(Wait(pkt, router_intf, dstipaddr))
            
            # 对队列中所有包尝试转发并删除某些包（成功转发和ARP请求将超过5次）
            repeat = []         # 存储之前已经发送过ARP请求的包的目的地址
            to_delete = []      # 存储将要被删除的包
            for item in waiting_queue:
                flag = item.forwarding(cache, self.net, repeat)
                if flag == 0:
                    to_delete.append(item)
                elif flag == -1:
                    # ARP失败
                    # print("ARP失败")
                    prefix = 0
                    tempip = item.dstipaddr
                    for temp in waiting_queue:
                        if temp.dstipaddr == tempip:
                            packet = self.icmperr(temp.interface, temp.packet, ICMPType.DestinationUnreachable, 1)
                            prefix = 0
                            net, prefix = self.prefixmatch(forwarding_table, packet[1].dst)
                            if forwarding_table[net][0]:
                                dstipaddr = IPv4Address(forwarding_table[net][0])
                            else:
                                dstipaddr = packet[1].dst
                            # 找出转发端口
                            interface = forwarding_table[net][1]
                            for intf in my_interfaces:
                                if intf.name == interface:
                                    router_intf = intf
                                    break
                            packet[0].src = router_intf.ethaddr
                            packet[1].src = router_intf.ipaddr
                            # 将数据包和端口、目标地址打包成一个类对象加入队列
                            waiting_queue.append(Wait(packet, router_intf, dstipaddr))
                            to_delete.append(temp)
            for i in to_delete:
                waiting_queue.remove(i)


def main(net):
    '''
    Main entry point for router.  Just create Router
    object and get it going.
    '''
    r = Router(net)
    r.router_main()
    net.shutdown()
