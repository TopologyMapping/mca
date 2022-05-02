import ipaddress
import time
from collections.abc import Sequence

import mca.record as record
import mca.probe as probe
import mca.topology as topology
import mca.probing as probing
import mca.identifiers as identifiers


class MCA:

    nprobes = {
        90: [
            0, 1, 5, 9, 13, 18, 23, 28, 33, 38, 44, 50, 55, 61, 67, 73, 79,
            85, 91, 97, 103, 109, 116, 122, 128, 135, 141, 148, 154, 161, 168,
            174, 181, 188, 194, 201, 208, 215, 222, 229, 235, 242, 249, 256,
            263, 270, 277, 285, 292, 299, 306, 313, 320, 327, 335, 342, 349
        ],
        95: [
            0, 1, 6, 11, 16, 21, 27, 33, 38, 44, 51, 57, 63, 70, 76, 83, 90,
            96, 103, 110, 117, 124, 131, 138, 145, 152, 159, 167, 174, 181,
            189, 196, 203, 211, 218, 226, 233, 241, 248, 256, 264, 271, 279,
            287, 294, 302, 310, 318, 326, 333, 341, 349, 357, 365, 373, 381,
            389
        ],
        99: [
            0, 1, 8, 15, 21, 28, 36, 43, 51, 58, 66, 74, 82, 90, 98, 106,
            115, 123, 132, 140, 149, 157, 166, 175, 183, 192, 201, 210, 219,
            228, 237, 246, 255, 264, 273, 282, 291, 300, 309, 319, 328, 337,
            347, 356, 365, 375, 384, 393, 403, 412, 422, 431, 441, 450, 460,
            470, 479
        ]
    }

    def __init__(self,
                 dst_ip: str,
                 max_ttl: int,
                 alpha: int,
                 max_nh: int,
                 max_border: int,
                 gap_limit: int,
                 fields: Sequence[str],
                 max_attempts: int,
                 wait_timeout: int,
                 probe_type: str,
                 pps: int,
                 instance_id: int) -> None:

        self.ip_version = ipaddress.ip_address(dst_ip).version
        self.topology = topology.Topology()
        self.identifiers = identifiers.Identifiers(fields)

        self.probing = probing.Probing(
            dst_ip, self.ip_version, max_attempts, wait_timeout, probe_type,
            pps, instance_id, self.identifiers
        )

        self.record_data = record.Record()
        self.max_ttl = max_ttl
        self.alpha = alpha
        self.max_nh = max_nh
        self.max_border = max_border
        self.gap_limit = gap_limit
        self.fields = fields
        self.dst_ip = dst_ip
        self.src_ip = self.probing.src_ip
        self.halt_ttl = 0

    def write_record(self, record_type, data):
        if self.record_data:
            self.record_data.write_record(record_type, data)

    def send_flow_ids_ttl(self,
                          flow_ids: Sequence[tuple[int]],
                          ttl: int,
                          save: bool = True,
                          check_before: bool = True):
        """
        Send TTL limited probes, one for each flow identifier on the list.
        This function waits for all answers and retries.

        Args:
            flow_ids (Sequence[Sequence[int]]): List of tuples of flow id indexes.
                Each flow id index in the tuple corresponds to a specific field.
            ttl (int): destination TTL value for the probes to be sent.
            save (bool): whether the probes should be saved (Identifiers
                flow_ids_by_hop & flow_ids_by_hop_ip).
            check_before (bool): if True, check if a given probe was already sent
                for a given TTL, flow id and don't send again if that is the case.

        Returns:
            list[Probe]: List of the sent probes.
        """

        probes = []

        for f in flow_ids:
            # Check if the flowid was already sent in this ttl
            # if so we dont send it again if check_before is true
            if check_before:
                p = self.identifiers.get_probe_for_hop_and_flow_id(ttl, f)
                if p is not None:
                    probes.append(p)
                    continue

            # Create the probe
            p = probe.Probe(f, ttl, self.dst_ip)
            probes.append(p)

            if ttl == 0:
                p.answer_ip = self.src_ip
                continue

            self.probing.send_probe(p)

        self.probing.wait()

        if save:
            for p in probes:
                self.identifiers.store_probe_result(p)

        # TODO: save statistics
        for p in probes:
            self.topology.add_node(ttl, p.answer_ip, False)

        return probes

    def node_control(self, n, node, ttl, varying_field=False):
        """
        """

        if varying_field:
            flow_ids = self.identifiers.get_classify_flow_ids(
                ttl, node.ip, varying_field
            )
        else:
            flow_ids = self.identifiers.get_discovery_flow_ids(ttl, node.ip)

        # If not enough flow identifiers,
        # try to discover new by sending probes
        probes = []

        keep_trying = True
        while keep_trying and len(flow_ids) < n:

            if varying_field:
                new = self.identifiers.create_new_classify_flow_ids(
                    ttl, node.ip, varying_field, n - len(flow_ids)
                )
            else:
                new = self.identifiers.create_new_discovery_flow_ids(
                    ttl, n - len(flow_ids)
                )

            if len(new) < (n - len(flow_ids)):
                keep_trying = False

            ps = self.send_flow_ids_ttl(new, ttl)
            probes.extend(ps)

            for p in ps:
                if p.answer_ip == node.ip:
                    flow_ids.append(p.flowid)

        if len(probes) > 0:
            # Write node control record
            self.write_record('node_control', [
                ('ipaddr', node.ip),
                ('uint8', ttl),
                ('probe-list', probes)
            ])

        return flow_ids[:n]

    def next_hops(self, node, node_ttl, probe_ttl):
        """
        Probe a TTL with flow ids that passes trough a previous node
        Important: probe_ttl may not be node_ttl + 1 as this functions
            is used for exploring a per-packet load balancer diamond
        """

        next_hops = []
        new_next_hop = True
        probes = []

        while new_next_hop:
            total = 1 if len(next_hops) == 0 else len(next_hops)

            if (total + 1) >= len(self.nprobes[self.alpha]):
                break

            number_probes = self.nprobes[self.alpha][total + 1]

            flow_ids = self.node_control(number_probes, node, node_ttl)

            ps = self.send_flow_ids_ttl(flow_ids, probe_ttl)
            nh = {p.answer_ip for p in ps}

            # Do not include duplicated probes in the probes list
            for p in ps:
                if p not in probes:
                    probes.append(p)

            nh.discard(node.ip)  # Remove self loops
            nh.discard('*' + str(probe_ttl))  # Remove unresponsives

            # Check if we should stop
            new_next_hop = False
            for n in nh:
                if n not in next_hops:
                    if len(next_hops) < self.max_nh:
                        next_hops.append(n)
                        new_next_hop = True

            if len(next_hops) <= 1 or len(next_hops) >= self.max_nh:
                new_next_hop = False

        # Check if next hops is empty and add a unresponsive nh if so
        if len(next_hops) == 0:
            next_hops.append('*' + str(probe_ttl))

        # Add next hops to the topology
        for nh in next_hops:
            n = self.topology.add_node(probe_ttl, nh)
            n.mca_node = True

            n.add_parent(node)
            node.add_next_hop(n)

            # Halt if network unreachable or reply from the destination
            for p in probes:
                halt = (
                    p.answer_ip == nh and p.answer_type and (
                        'unreachable' in p.answer_type or
                        p.answer_type == 'reply'
                    )
                )
                if halt:
                    n.halt = True
                    n.halt_cause = p.answer_type
                    break

            # Check gap limit
            if self.topology.check_gap_limit(n, self.gap_limit):
                n.halt = True
                n.halt_cause = 'gap limit'

        node.explored_next_hops = True

        # Write next hops record
        self.write_record('next_hops', [
            ('ipaddr', node.ip),
            ('uint8', node_ttl),
            ('probe-list', probes),
            ('ipaddr-list', next_hops)
        ])

        for n in next_hops:
            print(node.ip + '->' + n)

        return next_hops

    def classify_result(self, node, ttl, flow_ids, field):
        save = True if field != 'per-packet' else False
        check_before = True if field != 'per-packet' else False

        probes = self.send_flow_ids_ttl(flow_ids, ttl + 1, save, check_before)

        next_hops = {p.answer_ip for p in probes}

        next_hops.discard(node.ip)  # Remove self loops
        next_hops.discard('*' + str(ttl + 1))  # Remove unresponsives

        result = True if len(next_hops) > 1 else False

        # Write classify record
        self.write_record('classify', [
            ('ipaddr', node.ip),
            ('uint8', ttl),
            ('string', field),
            ('probe-list', probes),
            ('uint8', 1 if result else 0)
        ])

        return result

    def classify(self, node, ttl):
        """
        Classify a node by the fields it uses for load balancing
        """

        number_probes = self.nprobes[self.alpha][2]

        # First, try to classify as per-packet
        flow_ids = self.node_control(1, node, ttl) * number_probes
        if self.classify_result(node, ttl, flow_ids, 'per-packet'):
            return ['per-packet']

        classification = []

        for field in self.fields:
            flow_ids = self.node_control(number_probes, node, ttl, field)
            if self.classify_result(node, ttl, flow_ids, field):
                classification.append(field)

        return classification

    def paris_traceroute(self) -> None:
        """
        Paris traceroute without varying the destination address.
        """

        probes = []
        path = []
        max_ttl = 0

        flow_id = list(self.identifiers.create_new_discovery_flow_id(0))

        if 'daddr' in self.fields:
            addr = int(ipaddress.ip_address(self.dst_ip))
            flow_id[self.fields.index('daddr')] = addr & 0xff

        flow_id = tuple(flow_id)

        probe = self.send_flow_ids_ttl([flow_id], 0)[0]
        path.append(probe.answer_ip)

        for ttl in range(0, self.max_ttl):
            border = self.topology.get_nodes_ttl(ttl)
            max_ttl = ttl

            if len(border) == 0:
                break

            node = border[0]

            probe = self.send_flow_ids_ttl([flow_id], ttl + 1)
            probe = probe[0]

            probes.append(probe)

            path.append(probe.answer_ip)

            # Add next hop to the topology
            new_node = self.topology.add_node(ttl=ttl + 1, ip=probe.answer_ip)
            new_node.add_parent(node)
            node.add_next_hop(new_node)

            # Halt if network unreachable or reply from the destination
            halt = (
                probe.answer_type and (
                    'unreachable' in probe.answer_type or
                    probe.answer_type == 'reply'
                )
            )

            if halt:
                new_node.halt = True
                new_node.halt_cause = probe.answer_type
                break

            # Check gap limit
            if self.topology.check_gap_limit(new_node, self.gap_limit):
                new_node.halt = True
                new_node.halt_cause = 'gap limit'
                break

        # Write paris traceroute record
        self.write_record('paris_traceroute', [
            ('probe-list', probes),
            ('ipaddr-list', path),
            ('uint8', max_ttl)
        ])

    def explore_per_packet_diamond(self, node, node_ttl):
        """
        Enumerate nodes in a per-packet diamond
        """

        # Start at node_ttl + 2 as next hops of node were already discovered
        for ttl in range(node_ttl + 2, self.max_ttl):
            next_hops = self.next_hops(node, node_ttl, ttl)
            for n in next_hops:
                n_node = self.topology.find_node(n)
                n_node.per_packet_traffic = True

            if len(next_hops) == 1:
                break

    def run(self) -> None:
        """Run MCA, collect statistics."""

        init_time = time.time()

        # Write header to the record
        self.write_record('header', [
            ('ipaddr', self.dst_ip),
            ('ipaddr', self.probing.src_ip),
            ('ipaddr', self.probing.gateway),
            ('string', self.probing.interface),
            ('string', self.probing.bpf_filter),
            ('string', self.probing.probe_type),
            ('uint32', self.probing.pps),
            ('uint8', self.probing.max_attempts),
            ('uint8', self.probing.wait_timeout),
            ('uint8', self.alpha),
            ('uint8', self.max_ttl),
            ('uint8', self.gap_limit),
            ('uint16', self.max_nh),
            ('uint16', self.max_border),
            ('string-list', self.fields),
        ])

        print('MCA to', self.dst_ip)

        self._run_mca()

        # Write halting causes
        halting_causes = []
        for n in self.topology.nodes:
            node = self.topology.nodes[n]
            if node.halt:
                halting_causes.append((node.ip, node.halt_cause))

        self.write_record('halting', [
            ('halting-list', halting_causes)
        ])

        finish_time = time.time()

        # Write statistics
        self.write_record('stats', [
            ('time', init_time),
            ('time', finish_time),
            ('uint32', self.probing.sent_packets),
            ('uint32', self.probing.matched_packets),
            ('uint32', self.probing.matches_on_retry),
            ('uint32', self.probing.retries),
            ('uint8', self.halt_ttl)
        ])

    def _run_mca(self) -> None:
        """
        Run the Multipath Classification Algorithm
        """

        root = self.topology.add_node(0, self.src_ip)
        root.mca_node = True

        self.paris_traceroute()

        for ttl in range(0, self.max_ttl):
            border = self.topology.get_nodes_ttl(ttl, True)

            if len(border) == 0:
                break

            if len(border) > self.max_border:
                self.halt_ttl = ttl
                break

            # Explore nodes in the border
            for node in border:
                ignore = (
                    node.halt or
                    node.explored_next_hops or
                    node.per_packet_traffic
                )

                if ignore:
                    continue

                # Enumerate next hops of node in ttl + 1
                next_hops = self.next_hops(node, ttl, ttl + 1)

                # Classify if more than one next hop have been found
                if len(next_hops) > 1:
                    fields = self.classify(node, ttl)

                    # If the node was classified as per-packet then
                    # all its next hops receive per-packet traffic
                    if 'per-packet' in fields:
                        for n in next_hops:
                            nh = self.topology.find_node(n)
                            nh.per_packet_traffic = True
                        self.explore_per_packet_diamond(node, ttl)

    def send_extended_classification_probe(self,
                                           flow_id_indices: tuple[int],
                                           extended_classification_flow_id_index: int,
                                           ttl: int):
        """
        Send one TTL limited extended classification probe.
        This function waits for all answers and retries.

        Args:
            flow_id_indices (tuple[int]): The flow indentifier
                indices used to find the given next interface
                of a load balancer during MDA.
            extended_classification_flow_id_index (int): a single
                index to be used for the given option/extension
                header for evaluating chaining correctness.
            ttl (int): The radius of the node being evaluated,
                child of a load balancer.

        Returns:
            list[Probe]: List of the sent probes.
        """
        p = probe.Probe(flow_id_indices, ttl, self.dst_ip, extended_classification_flow_id_index)
        self.probing.send_probe(p)
        self.probing.wait()
        return p

    def load_balancer_node_extclass_correctness(self, ttl: int, load_balancer_node: topology.Node) -> None:
        """Evaluates the chaining correctness of a node

        Resends the probe used to discover a child interface
        of a load balancer a given number of times, according to
        the level of confidence, adding either options (IPv4) or
        extension headers (IPv6) to evaluate the chaining
        correctness of the load balancer.

        Args:
            ttl (int): The radius of the node to be evaluated.
            load_balancer_node (topology.Node): The load balancer
                node to be evaluated for chaining correctness.

        Returns:
            None
        """

        probes_count = self.nprobes[self.alpha][2]
        child_node = load_balancer_node.next_hops[0]
        child_ttl = ttl + 1
        flow_id_indexes = self.identifiers.get_discovery_flow_ids(child_ttl, child_node.ip)[0]

        for _ in range(probes_count):
            extended_classification_flow_id_index = self.identifiers.create_new_extclass_flow_id_index(child_ttl, child_node.ip)
            probe = self.send_extended_classification_probe(flow_id_indexes, extended_classification_flow_id_index, child_ttl)
            if probe.answer_ip != child_node.ip:
                load_balancer_node.extclass_correctness = False
                return

    def run_extended_classification(self) -> None:
        """Runs the extended classification for the topology

        Evaluates the chaining correctness of each
        non per-packet load balancer node in
        the topology.

        Returns:
            None
        """
        for ttl in range(0, self.max_ttl):
            border = self.topology.get_nodes_ttl(ttl)
            for node in border:
                node_is_load_balancer = len(node.next_hops) > 1
                if not node.per_packet_traffic and node_is_load_balancer:
                    self.load_balancer_node_extclass_correctness(ttl, node)
