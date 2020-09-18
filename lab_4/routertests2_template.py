#!/usr/bin/env python


from switchyard.lib.userlib import *

def mk_arpreq(hwsrc, ipsrc, ipdst):
    return create_ip_arp_request(hwsrc, ipsrc, ipdst)

def mk_arpresp(arpreq, hwsrc, arphwsrc=None, arphwdst=None):
    if arphwsrc is None:
        arphwsrc = hwsrc
    if arphwdst is None:
        arphwdst = arpreq[1].senderhwaddr
    srcip = arpreq[1].targetprotoaddr
    targetip = arpreq[1].senderprotoaddr
    return create_ip_arp_reply(hwsrc, arphwdst, srcip, targetip)

def mk_ping(hwsrc, hwdst, ipsrc, ipdst, reply=False, ttl=64):
    ether = Ethernet()
    ether.src = hwsrc
    ether.dst = hwdst
    ippkt = IPv4()
    ippkt.src = ipsrc
    ippkt.dst = ipdst
    ippkt.ttl = ttl
    ippkt.ipid = 0
    icmppkt = ICMP()
    if reply:
        icmppkt.icmptype = ICMPType.EchoReply
    else:
        icmppkt.icmptype = ICMPType.EchoRequest
    icmppkt.icmpdata.sequence = 42
    icmppkt.icmpdata.data = b'stuff!'

    return ether + ippkt + icmppkt

def write_table():
    table = '''172.16.0.0 255.255.0.0 192.168.1.2 router-eth0
172.16.128.0 255.255.192.0 10.10.0.254 router-eth1
172.16.64.0 255.255.192.0 10.10.1.254 router-eth1
10.100.0.0 255.255.0.0 172.16.42.2 router-eth2
'''
    outfile = open('forwarding_table.txt', 'w')
    outfile.write(table)
    outfile.close() 

def router_stage2():
    s = TestScenario("Router stage 2 additional test 1")
    s.add_interface('router-eth0', '10:00:00:00:00:01', '192.168.1.1', '255.255.255.0')
    s.add_interface('router-eth1', '10:00:00:00:00:02', '10.10.0.1', '255.255.0.0')
    s.add_interface('router-eth2', '10:00:00:00:00:03', '172.16.42.1', '255.255.255.252')

    otroarp = mk_arpreq("10:00:00:00:00:02", "10.10.0.1", "10.10.1.254")
    otroarpresponse = mk_arpresp(otroarp, "11:22:33:44:55:66")

    s.expect(PacketInputEvent("router-eth1", otroarpresponse, display=Arp),
        "Router should receive an unsolicited ARP response for 10.10.1.254 on router-eth1 and do nothing at all.")
    s.expect(PacketInputTimeoutEvent(0.1),
            "Application should try to receive a packet, but then timeout")
    return s

write_table()
scenario = router_stage2()
