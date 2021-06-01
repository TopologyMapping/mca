import scapy.all
from scapy.layers.inet import _IPOption_HDR
from scapy.layers import inet6

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
