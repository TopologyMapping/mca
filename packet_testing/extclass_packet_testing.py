import argparse
import ipaddress
import scapy.all
from scapy.layers.inet import _IPOption_HDR
from scapy.layers import inet6


parser = argparse.ArgumentParser(description='Tests the packets used during the MCA extended classification step.')
parser.add_argument('-d', '--destination_ip', required=True,
                    help='The destination IP address for testing the packets.')
parser.add_argument('-s', '--send_packets', action='store_true',
                    help='Send the experiment packets.')


class IPOption_RFC3692_style_experiment(scapy.all.IPOption):
    name = "RFC3692-style experiment"
    copy_flag = 0
    optclass = 2
    option = 30
    fields_desc = [_IPOption_HDR,
                   scapy.all.ByteField("length", 4),
                   scapy.all.ShortField("value", 0)
                  ]

class IPv6ExtHdrRFC3692_style_experiment(inet6._IPv6ExtHdr):
    name = "IPv6 Extension Header - RFC3692-style experiment Header"
    fields_desc = [scapy.all.ByteEnumField("nh", 59, scapy.all.ipv6nh),
                   scapy.all.ByteField("length", 0),
                   scapy.all.ShortField("value", 0),
                   scapy.all.ShortField("padding1", 0),
                   scapy.all.ShortField("padding2", 0)
                  ]
    overload_fields = {scapy.all.IPv6: {"nh": 253}}


# Ading the RFC3692 class to the ipv6nhcls dict
inet6.ipv6nhcls[253] = IPv6ExtHdrRFC3692_style_experiment


class ExtClassExperiment:
    def __init__(self, destination_ip: str, send_packets: bool) -> None:
        self.__destination_ip = destination_ip
        self.__send_packets = send_packets

        self.__ip_version = ipaddress.ip_address(args.destination_ip).version

        if self.__ip_version == 4:
            _, self.__source_ip, _ = scapy.all.conf.route.route(args.destination_ip)
        elif self.__ip_version == 6:
            _, self.__source_ip, _ = scapy.all.conf.route6.route(args.destination_ip)

        self.__payload = 'http://www.dcc.ufmg.br/~cunha/hosted/ipv6-exthdr-balancing'

    def run(self):
        if self.__ip_version == 4:
            dest_ip = str(ipaddress.IPv4Address(self.__destination_ip))

            # IP packet to be used for udp, tcp and icmp
            ip_packet = scapy.all.IP(src=self.__source_ip, dst=dest_ip)
            ip_packet.options.append(IPOption_RFC3692_style_experiment(value=56059))

            udp_packet = scapy.all.Ether() / ip_packet / scapy.all.UDP() / self.__payload
            tcp_packet = scapy.all.Ether() / ip_packet / scapy.all.TCP() / self.__payload
            icmp_packet = scapy.all.Ether() / ip_packet / scapy.all.ICMP() / self.__payload

            if self.__send_packets:
                scapy.all.sendp(udp_packet)
                scapy.all.sendp(tcp_packet)
                scapy.all.sendp(icmp_packet)

        elif self.__ip_version == 6:
            dest_ip = str(ipaddress.IPv6Address(self.__destination_ip))

            ipv6_packet = scapy.all.IPv6(src=self.__source_ip, dst=dest_ip)

            # packet using the fragment header
            fragment_packet = scapy.all.Ether() / ipv6_packet / scapy.all.IPv6ExtHdrFragment(offset=56059)

            # Packets using RFC3692 - UDP, TCP, ICMP
            ipv6_rfc3692_header = IPv6ExtHdrRFC3692_style_experiment(value=56059)

            udp_packet = scapy.all.Ether() / ipv6_packet / ipv6_rfc3692_header / scapy.all.UDP() / self.__payload
            tcp_packet = scapy.all.Ether() / ipv6_packet / ipv6_rfc3692_header / scapy.all.TCP() / self.__payload
            icmp_packet = scapy.all.Ether() / ipv6_packet / ipv6_rfc3692_header / scapy.all.ICMPv6EchoRequest() / self.__payload

            if self.__send_packets:
                scapy.all.sendp(fragment_packet)
                scapy.all.sendp(udp_packet)
                scapy.all.sendp(tcp_packet)
                scapy.all.sendp(icmp_packet)

args = parser.parse_args()
ExtClassExperiment(args.destination_ip, args.send_packets).run()
