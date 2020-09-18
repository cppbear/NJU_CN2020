'''
Ethernet learning switch in Python.

Note that this file currently has the code to implement a "hub"
in it, not a learning switch.  (I.e., it's currently a switch
that doesn't learn.)
'''
from switchyard.lib.userlib import *
import time

def main(net):
    my_interfaces = net.interfaces() 
    mymacs = [intf.ethaddr for intf in my_interfaces]

    table = {}
    
    while True:
        try:
            timestamp, input_port, packet = net.recv_packet()
        except NoPackets:
            continue
        except Shutdown:
            return

        t = time.time()     # 记录当前时间
        table[packet[0].src] = [input_port, t]  # 用一个列表来存储端口和时间
        for mac in list(table.keys()):      # 需要先转换为List，因为直接遍历字典是不允许改变大小的
            if t - table[mac][1] >= 10.0:   # 比较是否超时
                del table[mac]
        
        log_debug ("In {} received packet {} on {}".format(net.name, packet, input_port))
        if packet[0].dst in mymacs:
            log_debug ("Packet intended for me")
        else:
            if packet[0].dst in table.keys():
                net.send_packet(table[packet[0].dst][0], packet)
            else:
                for intf in my_interfaces:
                    if input_port != intf.name:
                        log_debug ("Flooding packet {} to {}".format(packet, intf.name))
                        net.send_packet(intf.name, packet)
    net.shutdown()
