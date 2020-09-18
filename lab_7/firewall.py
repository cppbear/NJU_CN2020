from switchyard.lib.userlib import *
import time

def main(net):
    # assumes that there are exactly 2 ports
    portnames = [ p.name for p in net.ports() ]
    portpair = dict(zip(portnames, portnames[::-1]))

    rules = []
    # 读取防火墙配置
    with open("firewall_rules.txt") as file:
        for line in file:
            info = line.split()
            if info and info[0] != '#':
                rule = {}
                rule['state'] = info[0]
                rule['type'] = info[1]
                for i in range(2, len(info) - 1, 2):
                    rule[info[i]] = info[i + 1]
                if info[-1] == 'impair':
                    rule['impair'] = 1
                if info[-2] == 'ratelimit':
                    rule['tokens'] = int(rule['ratelimit'])
                rules.append(rule)
    print('rules OK!')
    # 设置计时器
    timer = time.time()

    while True:
        pkt = None
        try:
            timestamp,input_port,pkt = net.recv_packet(timeout=0.5)
        except NoPackets:
            pass
        except Shutdown:
            break
        # 添加令牌
        if time.time() - timer >= 0.5:
            for rule in rules:
                if 'tokens' in rule.keys():
                    if rule['tokens'] + int(rule['ratelimit']) / 2 <= 2 * int(rule['ratelimit']):
                        rule['tokens'] += int(rule['ratelimit']) / 2
            timer = time.time()

        if pkt is not None:
            #log_info("Pkt: {}".format(pkt))
            # This is logically where you'd include some  firewall
            # rule tests.  It currently just forwards the packet
            # out the other port, but depending on the firewall rules
            # the packet may be dropped or mutilated.
            if pkt.has_header(IPv4):
                i = 0
                for rule in rules:
                    i += 1
                    if rule['type'] == 'ip':
                        if rule['src'] != 'any':
                            if pkt[IPv4].src not in IPv4Network(rule['src']):
                                continue
                        if rule['dst'] != 'any':
                            if pkt[IPv4].dst not in IPv4Network(rule['dst']):
                                continue
                    elif rule['type'] == 'icmp':
                        if not pkt.has_header(ICMP):
                            continue
                        else:
                            if rule['src'] != 'any':
                                if pkt[IPv4].src not in IPv4Network(rule['src']):
                                    continue
                            if rule['dst'] != 'any':
                                if pkt[IPv4].dst not in IPv4Network(rule['dst']):
                                    continue
                    elif rule['type'] == 'tcp':
                        if pkt[IPv4].protocol != IPProtocol.TCP:
                            continue
                        else:
                            if rule['src'] != 'any':
                                if pkt[IPv4].src not in IPv4Network(rule['src']):
                                    continue
                            if rule['dst'] != 'any':
                                if pkt[IPv4].dst not in IPv4Network(rule['dst']):
                                    continue
                            if rule['srcport'] != 'any':
                                if pkt[TCP].src != int(rule['srcport']):
                                    continue
                            if rule['dstport'] != 'any':
                                if pkt[TCP].dst != int(rule['dstport']):
                                    continue
                    elif rule['type'] == 'udp':
                        if pkt[IPv4].protocol != IPProtocol.UDP:
                            continue
                        else:
                            if rule['src'] != 'any':
                                if pkt[IPv4].src not in IPv4Network(rule['src']):
                                    continue
                            if rule['dst'] != 'any':
                                if pkt[IPv4].dst not in IPv4Network(rule['dst']):
                                    continue
                            if rule['srcport'] != 'any':
                                if pkt[UDP].src != int(rule['srcport']):
                                    continue
                            if rule['dstport'] != 'any':
                                if pkt[UDP].dst != int(rule['dstport']):
                                    continue
                    
                    #print('match rule', i)
                    if rule['state'] == 'deny':
                        break
                    else:
                        if 'ratelimit' in rule.keys():
                            size = len(pkt) - len(pkt.get_header(Ethernet))
                            #print('size:', size, 'tokens:', rule['tokens'])
                            if size <= rule['tokens']:
                                rule['tokens'] -= size
                                net.send_packet(portpair[input_port], pkt)
                        elif 'impair' in rule.keys():
                            my_pkt = pkt[0] + pkt[1] + pkt[2]
                            my_pkt += b'01011100001'
                            net.send_packet(portpair[input_port], my_pkt)
                        else:
                            net.send_packet(portpair[input_port], pkt)
                        break
            else:
                net.send_packet(portpair[input_port], pkt)

            
    net.shutdown()
