import argparse
import ipaddress
import scapy.all


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
            ip_packet.options.append(scapy.all.IPOption_RR(length=7, pointer=8, routers=['1.0.0.0']))

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

            # Packets using Destination options - UDP, TCP, ICMP
            ipv6_dest_opt_header = scapy.all.IPv6ExtHdrDestOpt(options=scapy.all.PadN(optdata='0'))

            udp_packet = scapy.all.Ether() / ipv6_packet / ipv6_dest_opt_header / scapy.all.UDP() / self.__payload
            tcp_packet = scapy.all.Ether() / ipv6_packet / ipv6_dest_opt_header / scapy.all.TCP() / self.__payload
            icmp_packet = scapy.all.Ether() / ipv6_packet / ipv6_dest_opt_header / scapy.all.ICMPv6EchoRequest() / self.__payload

            if self.__send_packets:
                scapy.all.sendp(fragment_packet)
                scapy.all.sendp(udp_packet)
                scapy.all.sendp(tcp_packet)
                scapy.all.sendp(icmp_packet)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Tests the packets used during the MCA extended classification step.')
    parser.add_argument('-d', '--destination-ip', required=True,
                        help='The destination IP address to test.')
    parser.add_argument('-s', '--send-packets', action='store_true',
                        help='Send the experiment packets.')

    args = parser.parse_args()
    ExtClassExperiment(args.destination_ip, args.send_packets).run()
