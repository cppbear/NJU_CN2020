'''
Ethernet learning switch in Python.

Note that this file currently has the code to implement a "hub"
in it, not a learning switch.  (I.e., it's currently a switch
that doesn't learn.)
'''
from switchyard.lib.userlib import *

# 用于对字典排序时传递参数，这里是传优先级
def count(elem):
    return elem[1][1]


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

        if packet[0].src in table.keys():
            if table[packet[0].src][0] == input_port:   # 如果存在且端口，优先级降低
                table[packet[0].src][1] += 1
            else:                                       # 如果端口不一样了，就更新端口，优先级不变
                table[packet[0].src][0] = input_port
        else:
            if len(table) == 5:     # 判断表是否满
                temp = sorted(table.items(), key=count, reverse=True)   # 将表中的项目按优先级数字降序
                del table[temp[0][0]]       # 删除第一个，也即LRU表项
            table[packet[0].src] = [input_port, 0]      # 加入新表项，优先级最高
        for key in table.keys():        # 将其它所有表项的优先级降低
            if key != packet[0].src:
                table[key][1] += 1

        log_debug("In {} received packet {} on {}".format(net.name, packet, input_port))
        if packet[0].dst in mymacs:
            log_debug("Packet intended for me")
        else:
            if packet[0].dst in table.keys():
                table[packet[0].dst][1] = 0     # 将目的地址所在表项优先级升为最高
                net.send_packet(table[packet[0].dst][0], packet)
            else:
                for intf in my_interfaces:
                    if input_port != intf.name:
                        log_debug("Flooding packet {} to {}".format(packet, intf.name))
                        net.send_packet(intf.name, packet)
    net.shutdown()
