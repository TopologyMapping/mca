import ipaddress
import struct
import sys

import scapy.all


class Forge:

    def __init__(self, probe, src_ip, probe_type, ip_version, flow_ids):
        self.forge_fn = {
            'ip4': self.ipv4,
            'ip6': self.ipv6,
            'udp4': self.udp,
            'udp6': self.udp,
            'tcp4': self.tcp,
            'tcp6': self.tcp,
            'icmp4': self.icmp4,
            'icmp6': self.icmp6
        }

        self.src_ip = src_ip
        self.probe = probe
        self.flow_ids = flow_ids
        self.probe_type = probe_type
        self.ip_version = ip_version

    def forge(self):
        self.packet = scapy.all.Ether()
        self.forge_fn['ip' + str(self.ip_version)]()
        self.forge_fn[self.probe_type + str(self.ip_version)]()

        return self.packet

    def ipv4(self):
        dst = self.probe.dst
        if 'daddr' in self.flow_ids:
            dst = int(ipaddress.IPv4Address(dst)) & 0xffffff00 | self.flow_ids['daddr']
            dst = str(ipaddress.IPv4Address(dst))

        tos = self.flow_ids['tos'] if 'tos' in self.flow_ids else 0

        self.packet /= scapy.all.IP(src=self.src_ip, dst=dst, ttl=self.probe.ttl, tos=tos)

    def ipv6(self):
        dst = self.probe.dst
        if 'daddr' in self.flow_ids:
            dst = int(ipaddress.IPv6Address(dst)) & 0xffffffffffffffffffffffffffffff00 | self.flow_ids['daddr']
            dst = str(ipaddress.IPv6Address(dst))

        tc = self.flow_ids['tc'] if 'tc' in self.flow_ids else 0
        fl = self.flow_ids['fl'] if 'fl' in self.flow_ids else 0

        self.packet /= scapy.all.IPv6(src=self.src_ip, dst=dst, hlim=self.probe.ttl, tc=tc, fl=fl)

    def udp(self):
        sport = self.flow_ids['sport'] if 'sport' in self.flow_ids else 33434
        dport = self.flow_ids['dport'] if 'dport' in self.flow_ids else 33434

        if dport <= 256:
            dport += 33434

        self.packet /= scapy.all.UDP(sport=sport, dport=dport)

        # Add the probe id to the packet payload
        self.packet /= struct.pack(">H", self.probe.probe_id)

        # Cook the packet and initialize it again
        if sys.version_info[0] < 3:
            self.packet = scapy.all.Ether(str(self.packet))
        else:
            self.packet = scapy.all.Ether(scapy.all.raw(self.packet))

        # Switch payload and UDP checksum
        chksum = self.packet[scapy.all.UDP].chksum
        self.packet['UDP'].remove_payload()
        self.packet /= struct.pack(">H", chksum)

        self.packet[scapy.all.UDP].chksum = self.probe.probe_id

    def tcp(self):
        sport = self.flow_ids['sport'] if 'sport' in self.flow_ids else 33434
        dport = self.flow_ids['dport'] if 'dport' in self.flow_ids else 33434
        self.packet /= scapy.all.TCP(sport=sport, dport=dport, seq=self.probe.probe_id)

    def icmp4(self):
        flowid_chksum = self.flow_ids['chksum'] if 'chksum' in self.flow_ids else 1

        # Store the flowid in the seq number so the checksum (the real
        # flowid) is modified accordly
        self.packet /= scapy.all.ICMP(id=self.probe.probe_id, seq=flowid_chksum)

        # Cook the packet and initialize it again
        if sys.version_info[0] < 3:
            self.packet = scapy.all.Ether(str(self.packet))
        else:
            self.packet = scapy.all.Ether(scapy.all.raw(self.packet))

        # Switch ICMP seq and ICMP checksum
        chksum = self.packet[scapy.all.ICMP].chksum
        seqnum = self.packet[scapy.all.ICMP].seq
        self.packet[scapy.all.ICMP].chksum = seqnum
        self.packet[scapy.all.ICMP].seq = chksum

    def icmp6(self):
        flowid_chksum = self.flow_ids['chksum'] if 'chksum' in self.flow_ids else 1

        # Store the flowid in the seq number so the checksum (the real
        # flowid) is modified accordly
        self.packet /= scapy.all.ICMPv6EchoRequest(id=self.probe.probe_id, seq=flowid_chksum)

        # Cook the packet and initialize it again
        if sys.version_info[0] < 3:
            self.packet = scapy.all.Ether(str(self.packet))
        else:
            self.packet = scapy.all.Ether(scapy.all.raw(self.packet))

        # Switch ICMP seq and ICMP checksum
        cksum = self.packet[scapy.all.ICMPv6EchoRequest].cksum
        seqnum = self.packet[scapy.all.ICMPv6EchoRequest].seq
        self.packet[scapy.all.ICMPv6EchoRequest].cksum = seqnum
        self.packet[scapy.all.ICMPv6EchoRequest].seq = cksum
