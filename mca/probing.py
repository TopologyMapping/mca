import threading
import time

import scapy.all

import mca.forge as forge


class Probing:

    def __init__(self, dst_ip, ip_version, max_attempts, wait_timeout,
                 probe_type, pps, instance_id, identifiers):

        self.identifiers = identifiers
        self.probes = []
        self.current_probe_id = 0
        self.probes_lock = threading.Lock()
        self.sent_packets = 0
        self.matched_packets = 0
        self.matches_on_retry = 0
        self.retries = 0
        self.pps = pps
        self.wait_between = 1.0 / pps
        self.last_sent_time = None
        self.max_attempts = max_attempts
        self.probe_type = probe_type
        self.wait_timeout = wait_timeout
        self.instance_id = instance_id
        self.ip_version = ip_version

        if self.ip_version == 4:
            self.interface, self.src_ip, self.gateway = scapy.all.conf.route.route(dst_ip)
        elif self.ip_version == 6:
            self.interface, self.src_ip, self.gateway = scapy.all.conf.route6.route(dst_ip)

        # We match ICMP time exceeded and unreach for all probes
        # ICMP echo reply for ICMP v4 and v6 probes
        # and any TCP from the destination in response to a TCP probe
        filters = {
            'udp4': '(icmp and ip[20] == 11) or (icmp and ip[20] == 3)',
            'udp6': '(icmp6 and ip6[40] == 3) or (icmp6 and ip6[40] == 1)',
            'tcp4': '(icmp and ip[20] == 11) or (icmp and ip[20] == 3) or (ip and tcp)',
            'tcp6': '(icmp6 and ip6[40] == 3) or (icmp6 and ip6[40] == 1) or (ip6 and tcp)',
            'icmp4': '(icmp and ip[20] == 11) or (icmp and ip[20] == 0) or (icmp and ip[20] == 3)',
            'icmp6': '(icmp6 and ip6[40] == 3) or (icmp6 and ip6[40] == 129) or (icmp6 and ip6[40] == 1)',
        }

        filter_name = probe_type + str(self.ip_version)
        self.bpf_filter = filters[filter_name]
        self.init_sniff_thread()

    def get_new_probe_id(self):
        """
        Get a unique probe id between 1 and 255
        It includes the instance_id and needs 2 bytes to be stored
        """
        self.current_probe_id = (
            (self.current_probe_id + 1) if self.current_probe_id < 255 else 1
        )

        return (self.instance_id << 8) + self.current_probe_id

    def match_udp4(self, packet, p):
        if 'UDPerror' in packet:
            if p.probe_scapy['UDP'].chksum == packet['UDPerror'].chksum:
                answer_type = None
                if packet['ICMP'].type == 11:
                    answer_type = 'time exceeded'
                elif packet['ICMP'].type == 3:
                    answer_type = 'dst unreachable ' + str(packet['ICMP'].code)
                p.set_answer(packet['IP'].src, packet, answer_type)
                return True

        return False

    def match_udp6(self, packet, p):
        if 'UDPerror' in packet:
            if p.probe_scapy['UDP'].chksum == packet['UDPerror'].chksum:
                answer_type = None
                if packet.haslayer('ICMPv6TimeExceeded'):
                    answer_type = 'time exceeded'
                elif packet.haslayer('ICMPv6DestUnreach'):
                    answer_type = 'dst unreachable ' + str(packet['ICMPv6DestUnreach'].code)
                p.set_answer(packet['IPv6'].src, packet, answer_type)
                return True

        return False

    def match_tcp4(self, packet, p):
        if 'TCPerror' in packet:
            if p.probe_scapy['TCP'].seq == packet['TCPerror'].seq:
                answer_type = None
                if packet['ICMP'].type == 11:
                    answer_type = 'time exceeded'
                elif packet['ICMP'].type == 3:
                    answer_type = 'dst unreachable ' + str(packet['ICMP'].code)
                p.set_answer(packet['IP'].src, packet, answer_type)
                return True
        elif 'TCP' in packet:
            if p.probe_scapy['IP'].dst == packet['IP'].src and p.probe_scapy['TCP'].seq == (packet['TCP'].ack - 1):
                answer_type = 'reply'
                p.set_answer(packet['IP'].src, packet, answer_type)
                return True

        return False

    def match_tcp6(self, packet, p):
        if 'TCPerror' in packet:
            if p.probe_scapy['TCP'].seq == packet['TCPerror'].seq:
                answer_type = None
                if packet.haslayer('ICMPv6TimeExceeded'):
                    answer_type = 'time exceeded'
                elif packet.haslayer('ICMPv6DestUnreach'):
                    answer_type = 'dst unreachable ' + str(packet['ICMPv6DestUnreach'].code)
                # TODO: check if we are getting answer_type == NONE here
                # also check for other protocols
                p.set_answer(packet['IPv6'].src, packet, answer_type)
                return True
        elif 'TCP' in packet:
            if p.probe_scapy['IPv6'].dst == packet['IPv6'].src and p.probe_scapy['TCP'].seq == (packet['TCP'].ack - 1):
                answer_type = 'reply'
                p.set_answer(packet['IPv6'].src, packet, answer_type)
                return True

        return False

    def match_icmp4(self, packet, p):
        if 'ICMPerror' in packet:
            if p.probe_scapy['ICMP'].id == packet['ICMPerror'].id:
                answer_type = None
                if packet['ICMP'].type == 11:
                    answer_type = 'time exceeded'
                elif packet['ICMP'].type == 3:
                    answer_type = 'dst unreachable ' + str(packet['ICMP'].code)
                p.set_answer(packet['IP'].src, packet, answer_type)
                return True

        elif 'ICMP' in packet:
            if p.probe_scapy['ICMP'].id == packet['ICMP'].id:
                answer_type = 'reply'
                p.set_answer(packet['IP'].src, packet, answer_type)
                return True

        return False

    def match_icmp6(self, packet, p):
        if packet.haslayer('ICMPv6TimeExceeded') or packet.haslayer('ICMPv6DestUnreach'):
            if packet.haslayer('ICMPv6EchoRequest'):
                if p.probe_scapy['ICMPv6EchoRequest'].id == packet['ICMPv6EchoRequest'].id:
                    answer_type = None
                    if packet.haslayer('ICMPv6TimeExceeded'):
                        answer_type = 'time exceeded'
                    elif packet.haslayer('ICMPv6DestUnreach'):
                        answer_type = 'dst unreachable ' + str(packet['ICMPv6DestUnreach'].code)
                    p.set_answer(packet['IPv6'].src, packet, answer_type)
                    return True

        elif 'ICMPv6EchoReply' in packet:
            if p.probe_scapy['ICMPv6EchoRequest'].id == packet['ICMPv6EchoReply'].id:
                answer_type = 'reply'
                p.set_answer(packet['IPv6'].src, packet, answer_type)
                return True

        return False

    def match(self, packet):
        match_fn = {
            'udp4': self.match_udp4,
            'udp6': self.match_udp6,
            'tcp4': self.match_tcp4,
            'tcp6': self.match_tcp6,
            'icmp4': self.match_icmp4,
            'icmp6': self.match_icmp6,
        }

        self.probes_lock.acquire()

        for p in self.probes:
            if p.answer_time is None:
                if match_fn[self.probe_type + str(self.ip_version)](packet, p):
                    self.matched_packets += 1
                    if p.attempts > 1:
                        self.matches_on_retry += 1
                    p.notify()
                    break

        self.probes_lock.release()

    def sniff_target(self):
        scapy.all.sniff(
            store=False,
            iface=self.interface,
            filter=self.bpf_filter,
            prn=self.match
        )

    def init_sniff_thread(self):
        t = threading.Thread(target=self.sniff_target)
        t.daemon = True
        t.start()
        time.sleep(1)  # TODO: use scapy's callback

    def send_probe(self, probe):
        if self.interface is None:
            self.get_route(probe.dst)
            self.init_sniff_thread()

        if probe.probe_id == 0:
            probe.probe_id = self.get_new_probe_id()

        flow_ids = self.identifiers.flow_id_to_dict(probe.flowid)

        f = forge.Forge(
            probe,
            self.src_ip,
            self.probe_type,
            self.ip_version,
            flow_ids
        )
        probe.probe_scapy = f.forge()

        probe.timeout = self.wait_timeout

        # Add the probe to the queue
        self.probes_lock.acquire()
        self.probes.append(probe)
        self.send_probe_network(probe)
        self.probes_lock.release()

    def wait_to_send(self):
        now = time.time()
        if self.last_sent_time is not None:
            waited = now - self.last_sent_time
            if waited < self.wait_between:
                time.sleep(self.wait_between - waited)
        self.last_sent_time = now

    def send_probe_network(self, probe):
        self.wait_to_send()
        sent_packet = scapy.all.sendp(
            probe.probe_scapy,
            verbose=False,
            return_packets=True
        )
        sent_packet = sent_packet[0]
        probe.set_attempt(sent_packet)
        self.sent_packets += 1

    def wait(self):
        """
        Wait for all answers or timeouts
        """
        while len(self.probes):
            self.probes_lock.acquire()
            p = self.probes[0]

            if p.answer_time is None and not p.timed_out():
                # Release the lock so the sniffer thread
                # can match the probe while we wait
                self.probes_lock.release()
                p.wait()
                self.probes_lock.acquire()  # Lock again

            # Check if need to retry the probe
            if p.answer_time is None and p.attempts < self.max_attempts:
                p = self.probes.pop(0)
                self.probes.append(p)
                self.send_probe_network(p)
                self.retries += 1
            else:
                self.probes.pop(0)

            self.probes_lock.release()
