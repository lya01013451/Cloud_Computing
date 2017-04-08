from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.ofproto import ether
from ryu.ofproto import inet
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import arp
from ryu.lib.packet import ipv4
from ryu.lib.packet import tcp
from ryu.lib.packet import udp

class SimpleSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
        #self.mac_to_port={}
        self.arp_table={}
        self.arp_table['10.0.0.1'] = '00:00:00:00:00:01'
        self.arp_table['10.0.0.2'] = '00:00:00:00:00:02'
        self.arp_table['10.0.0.3'] = '00:00:00:00:00:03'
        self.arp_table['10.0.0.4'] = '00:00:00:00:00:04'

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

        if datapath.id == 1:
            self.add_layer4_rules(datapath, inet.IPPROTO_TCP, '10.0.0.1', 10, 1)
            self.add_layer4_rules(datapath, inet.IPPROTO_TCP, '10.0.0.2', 10, 2)
            self.add_layer4_rules(datapath, inet.IPPROTO_TCP, '10.0.0.3', 10, 2)
            self.add_layer4_rules(datapath, inet.IPPROTO_TCP, '10.0.0.4', 10, 2)

            self.add_layer4_rules(datapath, inet.IPPROTO_ICMP, '10.0.0.1', 10, 1)
            self.add_layer4_rules(datapath, inet.IPPROTO_ICMP, '10.0.0.2', 10, 2)
            self.add_layer4_rules(datapath, inet.IPPROTO_ICMP, '10.0.0.3', 10, 2)
            self.add_layer4_rules(datapath, inet.IPPROTO_ICMP, '10.0.0.4', 10, 2)

            self.add_layer4_rules(datapath, inet.IPPROTO_UDP, '10.0.0.1', 10, 1)
            self.add_layer4_rules(datapath, inet.IPPROTO_UDP, '10.0.0.2', 10, 2)
            self.add_layer4_rules(datapath, inet.IPPROTO_UDP, '10.0.0.3', 10, 3)
            self.add_layer4_rules(datapath, inet.IPPROTO_UDP, '10.0.0.4', 10, 3)

            drop_tcp = parser.OFPMatch(eth_type=ether.ETH_TYPE_IP,
                                       ipv4_src='10.0.0.1',
                                       ipv4_dst='10.0.0.3',
                                       ip_proto=inet.IPPROTO_TCP,
                                       tcp_src=80)
            actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                             ofproto.OFPCML_NO_BUFFER)]
            self.add_flow(datapath, 20, drop_tcp, actions)

            drop_tcp = parser.OFPMatch(eth_type=ether.ETH_TYPE_IP,
                                       ipv4_src='10.0.0.1',
                                       ipv4_dst='10.0.0.3',
                                       ip_proto=inet.IPPROTO_TCP,
                                       tcp_dst=80)
            actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                              ofproto.OFPCML_NO_BUFFER)]
            self.add_flow(datapath, 20, drop_tcp, actions)



        elif datapath.id == 2:
            self.add_layer4_rules(datapath, inet.IPPROTO_TCP, '10.0.0.1', 10, 2)
            self.add_layer4_rules(datapath, inet.IPPROTO_TCP, '10.0.0.2', 10, 1)
            self.add_layer4_rules(datapath, inet.IPPROTO_TCP, '10.0.0.3', 10, 3)
            self.add_layer4_rules(datapath, inet.IPPROTO_TCP, '10.0.0.4', 10, 3)

            self.add_layer4_rules(datapath, inet.IPPROTO_ICMP, '10.0.0.1', 10, 2)
            self.add_layer4_rules(datapath, inet.IPPROTO_ICMP, '10.0.0.2', 10, 1)
            self.add_layer4_rules(datapath, inet.IPPROTO_ICMP, '10.0.0.3', 10, 3)
            self.add_layer4_rules(datapath, inet.IPPROTO_ICMP, '10.0.0.4', 10, 3)

            self.add_layer4_rules(datapath, inet.IPPROTO_UDP, '10.0.0.1', 10, 2)
            self.add_layer4_rules(datapath, inet.IPPROTO_UDP, '10.0.0.2', 10, 1)
            self.add_layer4_rules(datapath, inet.IPPROTO_UDP, '10.0.0.3', 10, 2)
            self.add_layer4_rules(datapath, inet.IPPROTO_UDP, '10.0.0.4', 10, 2)

            drop_udp=parser.OFPMatch(eth_type = ether.ETH_TYPE_IP,
                                     ipv4_src = '10.0.0.2',
                                     ipv4_dst = '10.0.0.3',
                                     ip_proto = inet.IPPROTO_UDP)
            actions=[]
            self.add_flow(datapath, 20, drop_udp, actions)



        elif datapath.id == 3:
            self.add_layer4_rules(datapath, inet.IPPROTO_TCP, '10.0.0.1', 10, 2)
            self.add_layer4_rules(datapath, inet.IPPROTO_TCP, '10.0.0.2', 10, 2)
            self.add_layer4_rules(datapath, inet.IPPROTO_TCP, '10.0.0.3', 10, 1)
            self.add_layer4_rules(datapath, inet.IPPROTO_TCP, '10.0.0.4', 10, 3)

            self.add_layer4_rules(datapath, inet.IPPROTO_ICMP, '10.0.0.1', 10, 2)
            self.add_layer4_rules(datapath, inet.IPPROTO_ICMP, '10.0.0.2', 10, 2)
            self.add_layer4_rules(datapath, inet.IPPROTO_ICMP, '10.0.0.3', 10, 1)
            self.add_layer4_rules(datapath, inet.IPPROTO_ICMP, '10.0.0.4', 10, 3)

            self.add_layer4_rules(datapath, inet.IPPROTO_UDP, '10.0.0.1', 10, 3)
            self.add_layer4_rules(datapath, inet.IPPROTO_UDP, '10.0.0.2', 10, 3)
            self.add_layer4_rules(datapath, inet.IPPROTO_UDP, '10.0.0.3', 10, 1)
            self.add_layer4_rules(datapath, inet.IPPROTO_UDP, '10.0.0.4', 10, 3)

            drop_udp = parser.OFPMatch(eth_type=ether.ETH_TYPE_IP,
                                       ipv4_src='10.0.0.3',
                                       ipv4_dst='10.0.0.2',
                                       ip_proto=inet.IPPROTO_UDP)
            actions = []
            self.add_flow(datapath, 20, drop_udp, actions)

            drop_tcp = parser.OFPMatch(eth_type=ether.ETH_TYPE_IP,
                                       ipv4_src='10.0.0.3',
                                       ipv4_dst='10.0.0.1',
                                       ip_proto=inet.IPPROTO_TCP,
                                       tcp_src=80)
            actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                              ofproto.OFPCML_NO_BUFFER)]
            self.add_flow(datapath, 30, drop_tcp, actions)

            drop_tcp = parser.OFPMatch(eth_type=ether.ETH_TYPE_IP,
                                       ipv4_src='10.0.0.3',
                                       ipv4_dst='10.0.0.1',
                                       ip_proto=inet.IPPROTO_TCP,
                                       tcp_dst=80)
            actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                              ofproto.OFPCML_NO_BUFFER)]
            self.add_flow(datapath, 30, drop_tcp, actions)

        elif datapath.id == 4:
            self.add_layer4_rules(datapath, inet.IPPROTO_TCP, '10.0.0.1', 10, 3)
            self.add_layer4_rules(datapath, inet.IPPROTO_TCP, '10.0.0.2', 10, 3)
            self.add_layer4_rules(datapath, inet.IPPROTO_TCP, '10.0.0.3', 10, 3)
            self.add_layer4_rules(datapath, inet.IPPROTO_TCP, '10.0.0.4', 10, 1)

            self.add_layer4_rules(datapath, inet.IPPROTO_ICMP, '10.0.0.1', 10, 3)
            self.add_layer4_rules(datapath, inet.IPPROTO_ICMP, '10.0.0.2', 10, 3)
            self.add_layer4_rules(datapath, inet.IPPROTO_ICMP, '10.0.0.3', 10, 3)
            self.add_layer4_rules(datapath, inet.IPPROTO_ICMP, '10.0.0.4', 10, 1)

            self.add_layer4_rules(datapath, inet.IPPROTO_UDP, '10.0.0.1', 10, 2)
            self.add_layer4_rules(datapath, inet.IPPROTO_UDP, '10.0.0.2', 10, 2)
            self.add_layer4_rules(datapath, inet.IPPROTO_UDP, '10.0.0.3', 10, 3)
            self.add_layer4_rules(datapath, inet.IPPROTO_UDP, '10.0.0.4', 10, 1)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        in_port = msg.match['in_port']
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        ethertype = eth.ethertype

        # process ARP
        if ethertype == ether.ETH_TYPE_ARP:
            self.handle_arp(datapath, in_port, pkt)
            return

        # process IP
        if ethertype == ether.ETH_TYPE_IP:
            self.handle_ip(datapath, in_port, pkt)
            return

    def add_layer4_rules(self, datapath, ip_proto, ipv4_dst = None, priority = 1, fwd_port = None):
        parser = datapath.ofproto_parser
        actions = [parser.OFPActionOutput(fwd_port)]
        match = parser.OFPMatch(eth_type = ether.ETH_TYPE_IP,
                                ip_proto = ip_proto,
                                ipv4_dst = ipv4_dst)

        self.add_flow(datapath, priority, match, actions)

    def add_flow(self, datapath, priority, match, actions):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]

        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                match=match, instructions=inst)
        datapath.send_msg(mod)

    def handle_arp(self, datapath, in_port, pkt):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        eth_pkt = pkt.get_protocol(ethernet.ethernet)
        arp_pkt = pkt.get_protocol(arp.arp)
        arp_resolv_mac = self.arp_table[arp_pkt.dst_ip]
        arp_response = packet.Packet()
        arp_response.add_protocol(ethernet.ethernet(dst=eth_pkt.src,
                                                    src=arp_resolv_mac,
                                                    ethertype=ether.ETH_TYPE_ARP))
        arp_response.add_protocol(arp.arp(hwtype=1,
                                          proto=0x0800, hlen=6, plen=4, opcode=2, src_mac=arp_resolv_mac,
                                          src_ip=arp_pkt.dst_ip, dst_mac=eth_pkt.src, dst_ip=arp_pkt.src_ip))
        arp_response.serialize()
        actions = [parser.OFPActionOutput(in_port)]
        out = parser.OFPPacketOut(datapath, ofproto.OFP_NO_BUFFER,
                                  ofproto.OFPP_CONTROLLER, actions, arp_response.data)
        datapath.send_msg(out)

    def handle_ip(self, datapath, in_port, pkt):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        eth_pkt = pkt.get_protocol(ethernet.ethernet)
        ipv4_pkt = pkt.get_protocol(ipv4.ipv4)
        tcp_pkt = pkt.get_protocol(tcp.tcp)
        tcp_response = packet.Packet()
        tcp_response.add_protocol(ethernet.ethernet(dst=eth_pkt.src,
                                                    src=eth_pkt.dst,
                                                    ethertype=eth_pkt.ethertype))
        tcp_response.add_protocol(ipv4.ipv4(dst=ipv4_pkt.src,
                                            src=ipv4_pkt.dst,
                                            proto=ipv4_pkt.proto))
        tcp_response.add_protocol(tcp.tcp(dst_port=tcp_pkt.src_port,
                                          src_port=tcp_pkt.dst_port,
                                          bits=tcp.TCP_RST))

        tcp_response.serialize()
        actions = [parser.OFPActionOutput(in_port)]
        out = parser.OFPPacketOut(datapath, ofproto.OFP_NO_BUFFER,
                                  ofproto.OFPP_CONTROLLER, actions, tcp_response.data)
        datapath.send_msg(out)



        """if datapath.id == 1 and ipv4_pkt.proto == inet.IPPROTO_TCP:
            eth_pkt = pkt.get_protocol(ethernet.ethernet)
            tcp_pkt = pkt.get_protocol(tcp.tcp)
            tcp_response = packet.Packet()
            tcp_response.add_protocol(ethernet.ethernet(ethertype=ether.ETH_TYPE_IP, dst=eth_pkt.src, src=eth_pkt.dst))
            tcp_response.add_protocol(ipv4.ipv4(dst=ipv4_pkt.src, src=ipv4_pkt.dst, proto=ipv4_pkt.proto))
            tcp_response.add_protocol(tcp.tcp(ack=tcp_pkt.seq + 1, src_port=tcp_pkt.dst_port, dst_port=tcp_pkt.src_port, bits=20))
            tcp_response.serialize()
            actions = [parser.OFPActionOutput(in_port)]
            out = parser.OFPPacketOut(datapath, ofproto.OFP_NO_BUFFER,
                                      ofproto.OFPP_CONTROLLER, actions, tcp_response.data)
            datapath.send_msg(out)

        if datapath.id == 3 and ipv4_pkt.proto == inet.IPPROTO_TCP:
            eth_pkt = pkt.get_protocol(ethernet.ethernet)
            tcp_pkt = pkt.get_protocol(tcp.tcp)
            tcp_response = packet.Packet()
            tcp_response.add_protocol(ethernet.ethernet(ethertype=ether.ETH_TYPE_IP, dst=eth_pkt.src, src=eth_pkt.dst))
            tcp_response.add_protocol(ipv4.ipv4(dst=ipv4_pkt.src, src=ipv4_pkt.dst, proto=ipv4_pkt.proto))
            tcp_response.add_protocol(tcp.tcp(ack=tcp_pkt.seq + 1, src_port=tcp_pkt.dst_port, dst_port=tcp_pkt.src_port, bits=20))
            tcp_response.serialize()
            actions = [parser.OFPActionOutput(in_port)]
            out = parser.OFPPacketOut(datapath, ofproto.OFP_NO_BUFFER,
                                      ofproto.OFPP_CONTROLLER, actions, tcp_response.data)
            datapath.send_msg(out)"""



# Cloud_Computing
