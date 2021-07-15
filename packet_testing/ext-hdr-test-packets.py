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

            # NOTE: (1) The pointer field is 1-based (first byte has index 1)
            #       (2) length field works correctly for values below 39
            ip_packet.options.append(scapy.all.IPOption_RR(length=7, pointer=8, routers=['1.0.0.0']))

            udp_packet = scapy.all.Ether() / ip_packet / scapy.all.UDP(dport=50001) / self.__payload
            tcp_packet = scapy.all.Ether() / ip_packet / scapy.all.TCP(dport=50000) / self.__payload
            icmp_packet = scapy.all.Ether() / ip_packet / scapy.all.ICMP() / self.__payload

            if self.__send_packets:
                scapy.all.sendp(udp_packet)
                scapy.all.sendp(tcp_packet)
                scapy.all.sendp(icmp_packet)

        elif self.__ip_version == 6:
            dest_ip = str(ipaddress.IPv6Address(self.__destination_ip))

            ipv6_packet = scapy.all.IPv6(src=self.__source_ip, dst=dest_ip)

            # Packets using Destination options - UDP, TCP, ICMP
            # NOTE: Directly passing the length argument to IPv6ExtHdrDestOpt does not
            # yield the padded result, so we're resorting to filling in optdata directly.
            ipv6_dest_opt_header = scapy.all.IPv6ExtHdrDestOpt(options=scapy.all.PadN(optdata='0'))

            udp_packet = scapy.all.Ether() / ipv6_packet / ipv6_dest_opt_header / scapy.all.UDP(dport=50001) / self.__payload
            tcp_packet = scapy.all.Ether() / ipv6_packet / ipv6_dest_opt_header / scapy.all.TCP(dport=50000) / self.__payload
            icmp_packet = scapy.all.Ether() / ipv6_packet / ipv6_dest_opt_header / scapy.all.ICMPv6EchoRequest() / self.__payload

            if self.__send_packets:
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
