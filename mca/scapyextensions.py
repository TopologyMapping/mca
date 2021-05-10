import scapy.all
from scapy.layers.inet import _IPOption_HDR

class IPOption_RFC3692_style_experiment(scapy.all.IPOption):
    name = "RFC3692-style experiment"
    copy_flag = 0
    optclass = 2
    option = 30
    fields_desc = [_IPOption_HDR,
                   scapy.all.ByteField("length", 4),
                   scapy.all.ShortField("value", 0)
                  ]
