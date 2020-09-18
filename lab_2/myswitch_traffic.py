'''
Ethernet learning switch in Python.

Note that this file currently has the code to implement a "hub"
in it, not a learning switch.  (I.e., it's currently a switch
that doesn't learn.)
'''
from switchyard.lib.userlib import *


# 用于对字典排序时传递参数，这里是传记录流量的数据
def count(elem):
    return elem[1][1]


def main(net):
    my_interfaces = net.interfaces() 
    mymacs = [intf.ethaddr for intf in my_interfaces]

    table = {}

    while True:
        try:
            timestamp,input_port,packet = net.recv_packet()
        except NoPackets:
            continue
        except Shutdown:
            return
        
        if packet[0].src in table.keys():
            table[packet[0].src][0] = input_port    # 更新已存在的地址对应的端口
        else:
            if len(table) == 5:
                temp = sorted(table.items(), key=count)     # 将表项按流量多少升序排列
                del table[temp[0][0]]       # 删除第1个，也即流量最少的地址对应的表项
            table[packet[0].src] = [input_port, 0]      # 添加新表项，流量为0

        log_debug ("In {} received packet {} on {}".format(net.name, packet, input_port))
        if packet[0].dst in mymacs:
            log_debug ("Packet intended for me")
        else:
            if packet[0].dst in table.keys():
                table[packet[0].dst][1] += 1    # 将目的地址对应的表项的流量加1
                net.send_packet(table[packet[0].dst][0], packet)
            else:
                for intf in my_interfaces:
                    if input_port != intf.name:
                        log_debug("Flooding packet {} to {}".format(packet, intf.name))
                        net.send_packet(intf.name, packet)
    net.shutdown()
